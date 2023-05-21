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

  defp bitstringToName(body, nameRaw, accumulator \\ [])

  defp bitstringToName(
         _body,
         <<0::8, remainder::binary>>,
         accumulator
       ) do
    {accumulator, remainder}
  end

  defp bitstringToName(
         body,
         <<len::8, domainParts::binary-size(len), remainder::binary>>,
         accumulator
       ) do
    bitstringToName(body, remainder, accumulator ++ [domainParts])
  end

  defp bitstringToName(
         body,
         <<1::1, 1::1, pointer::14, remainder::binary>>,
         accumulator
       ) do
    <<_::binary-size(pointer - 12), nameRaw::binary>> = body
    {name, _} = bitstringToName(body, nameRaw)
    {accumulator ++ name, remainder}
  end

  defp bitstringToQuestion(bitstring) do
    {domainParts, <<type::16, class::16, remainder::binary>>} =
      bitstringToName(bitstring, bitstring)

    domain = Enum.join(domainParts, ".")

    {%Resolver.Question{
       name: domain,
       type: type,
       class: class
     }, remainder}
  end

  defp bitstringToAnswer(body, answer) do
    {name, <<type::16, 1::16, ttl::32, len::16, data::binary-size(len), remainder::binary>>} =
      bitstringToName(body, answer)

    parsedData =
      case type do
        1 ->
          bitstringToIP(data)

        5 ->
          {return, _} = bitstringToName(body, data)
          Enum.join(return, ".")

        _ ->
          {:unknowntype}
      end

    {%Resolver.Answer{
       name: Enum.join(name, "."),
       type: type,
       class: 1,
       ttl: ttl,
       data: parsedData
     }, remainder}
  end

  defp bitstringToIP(bitstring) do
    octets =
      for <<octet::8 <- bitstring>> do
        octet
      end

    Enum.join(octets, ".")
  end

  defp unpackDNSResponse(<<headerRaw::binary-size(12), body::binary>>) do
    header = bitstringToHeader(headerRaw)

    {question, answerRaw} = bitstringToQuestion(body)

    {answers, _} =
      Enum.reduce(1..header.num_answers, {[], answerRaw}, fn _, {answers, remainder} ->
        {answer, answerRaw} = bitstringToAnswer(body, remainder)
        {[answer | answers], answerRaw}
      end)

    {header, question, answers}
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
