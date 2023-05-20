defmodule Resolver do
  import Bitwise

  defmodule Header do
    defstruct id: nil,
              flags: nil,
              num_questions: 0,
              num_answers: 0,
              num_authorities: 0,
              num_additionals: 0
  end

  defmodule Question do
    defstruct [:name, :type, :class]
  end

  defmodule Record do
    defstruct [:name, :type, :class, :ttl, :data]
  end

  defp headerToBitstring(%Header{} = header) do
    <<header.id::16, header.flags::binary, header.num_questions::16, header.num_answers::16,
      header.num_authorities::16, header.num_additionals::16>>
  end

  defp bitstringToHeader(
         <<id::16, flags::16, num_questions::16, num_answers::16, num_authorities::16,
           num_additionals::16>>
       ) do
    %Resolver.Header{
      id: id,
      flags: flags,
      num_questions: num_questions,
      num_answers: num_answers,
      num_authorities: num_authorities,
      num_additionals: num_additionals
    }
  end

  defp questionToBitstring(%Question{} = question) do
    <<question.name::binary, question.type::16, question.class::16>>
  end

  defp bitstringToQuestion(bitstring, accumulator \\ []) do
    <<len::8, domainParts::binary-size(len), remainder::binary>> = bitstring

    if len == 0 do
      {accumulator, remainder}
    else
      bitstringToQuestion(remainder, accumulator ++ [domainParts])
    end
  end

  defp unpackDNSResponse(<<headerRaw::binary-size(12), remainder::binary>>) do
    header = bitstringToHeader(headerRaw)

    {domainParts, remainder} = bitstringToQuestion(remainder)
    {header, domainParts, remainder}
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
    header = headerToBitstring(%Header{id: id, flags: flags, num_questions: 1})
    question = questionToBitstring(%Question{name: name, type: recordType, class: 1})
    header <> question
  end

  def query(domain) do
    dnsPacket = buildQuery(domain, 1)
    {:ok, socket} = :gen_udp.open(0, [:binary, active: false])
    :ok = :gen_udp.send(socket, {8, 8, 8, 8}, 53, dnsPacket)

    return =
      with {:ok, {_address, _port, data}} <- :gen_udp.recv(socket, 1024, :infinity) do
        unpackDNSResponse(data)
      else
        {:error, :closed} ->
          {:ok, nil}

        {:error, reason} ->
          {:error, reason}
      end

    :gen_udp.close(socket)
    return
  end
end
