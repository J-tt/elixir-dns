defmodule Resolver do
  import Bitwise

  defmodule DNSHeader do
    defstruct id: nil,
              flags: nil,
              num_questions: 0,
              num_answers: 0,
              num_authorities: 0,
              num_additionals: 0
  end

  defmodule DNSQuestion do
    defstruct [:name, :type, :class]
  end

  defp headerToBitstring(%DNSHeader{} = header) do
    <<header.id::16, header.flags::binary, header.num_questions::16, header.num_answers::16,
      header.num_authorities::16, header.num_additionals::16>>
  end

  defp questionToBitstring(%DNSQuestion{} = question) do
    <<question.name::binary, question.type::16, question.class::16>>
  end

  defp encodeName(name) do
    encodedName =
      name
      |> String.split(".")
      |> Enum.map(fn namePart ->
        <<String.length(namePart), namePart::binary>>
      end)
      |> Enum.join("")

    encodedName <> <<0>>
  end

  defp buildQuery(name, recordType) do
    name = encodeName(name)
    id = :rand.uniform(65535)
    flags = <<1 <<< 8::16>>
    header = headerToBitstring(%DNSHeader{id: id, flags: flags, num_questions: 1})
    question = questionToBitstring(%DNSQuestion{name: name, type: recordType, class: 1})
    header <> question
  end

  def query(domain) do
    dnsPacket = buildQuery(domain, 1)
    {:ok, socket} = :gen_udp.open(0, [:binary, active: false])
    :ok = :gen_udp.send(socket, {8, 8, 8, 8}, 53, dnsPacket)

    return =
      case :gen_udp.recv(socket, 1024, :infinity) do
        {:ok, {address, port, data}} ->
          {:ok, {data, {address, port}}}

        {:error, :closed} ->
          {:ok, nil}

        {:error, reason} ->
          {:error, reason}
      end

    :gen_udp.close(socket)
    return
  end
end
