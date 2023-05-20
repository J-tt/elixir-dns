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

  defmodule Answer do
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

  defp bitstringToName(bitstring, accumulator \\ [])

  defp bitstringToName(
         <<0::8, remainder::binary>>,
         accumulator
       ) do
    IO.puts("bitstring to name end")
    {accumulator, remainder}
  end

  defp bitstringToName(
         <<len::8, domainParts::binary-size(len), remainder::binary>>,
         accumulator
       ) do
    IO.puts("bitstring to name")
    bitstringToName(remainder, accumulator ++ [domainParts])
  end

  defp bitstringToName(
         <<1::1, 1::1, pointer::14, remainder::binary>>,
         _accumulator
       ) do
    IO.puts("bitstring to name compression: #{pointer}")
    "unknown"
  end

  defp bitstringToQuestion(bitstring) do
    {domainParts, <<type::16, class::16, remainder::binary>>} = bitstringToName(bitstring)
    domain = Enum.join(domainParts, ".")

    {%Resolver.Question{
       name: domain,
       type: type,
       class: class
     }, remainder}
  end

  defp bitstringToAnswer(bitstring) do
    {name, <<type::16, class::16, ttl::32, remainder::binary>>} = bitstringToName(bitstring)

    %Resolver.Answer{
      name: name,
      type: type,
      class: class,
      ttl: ttl,
      data: remainder
    }
  end

  defp unpackDNSResponse(<<headerRaw::binary-size(12), remainder::binary>>) do
    header = bitstringToHeader(headerRaw)

    {question, remainder} = bitstringToQuestion(remainder)
    answer = bitstringToAnswer(remainder)

    {header, question, answer}
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
