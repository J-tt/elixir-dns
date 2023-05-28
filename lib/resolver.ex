defmodule Resolver do
  import Bitwise

  defmodule Header do
    defstruct id: nil,
              flags: nil,
              num_questions: 0,
              num_answers: 0,
              num_authorities: 0,
              num_additionals: 0

    def toBitstring(%Header{} = header) do
      <<header.id::16, header.flags::binary, header.num_questions::16, header.num_answers::16,
        header.num_authorities::16, header.num_additionals::16>>
    end

    def fromBitstring(
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
  end

  defmodule Question do
    defstruct [:name, :type, :class]

    def toBitstring(%Question{} = question) do
      <<question.name::binary, question.type::16, question.class::16>>
    end

    def fromBitstring(bitstring) do
      {domainParts, <<type::16, class::16, remainder::binary>>} =
        Resolver.Name.fromBitstring(bitstring, bitstring)

      domain = Enum.join(domainParts, ".")

      {%Resolver.Question{
         name: domain,
         type: type,
         class: class
       }, remainder}
    end
  end

  defmodule Answer do
    defstruct [:name, :type, :class, :ttl, :data]

    def fromBitstring(body, answer) do
      {name, remainder} = Resolver.Name.fromBitstring(body, answer)

      IO.inspect(name, label: "name")
      IO.inspect(remainder, label: "remainder")

      # <<type::16, 1::16, ttl::32, len::16, data::binary-size(len), remainder::binary>> = remainder
      <<type::16, remainder::binary>> = remainder
      # data = <<192, 168, 1, 1>>

      {parsedData, ttl, remainder} =
        case {type, remainder} do
          {1, <<1::16, ttl::32, len::16, data::binary-size(len), remainder::binary>>} ->
            {Resolver.IP.fromBitstring(data), ttl, remainder}

          {5, <<1::16, ttl::32, len::16, data::binary-size(len), remainder::binary>>} ->
            {return, _} = Resolver.Name.fromBitstring(body, data)
            {Enum.join(return, "."), ttl, remainder}

          {2, <<1::16, ttl::32, len::16, data::binary-size(len), remainder::binary>>} ->
            {return, _} = Resolver.Name.fromBitstring(body, data)
            {Enum.join(return, "."), ttl, remainder}

          {28, <<1::16, ttl::32, len::16, data::binary-size(len), remainder::binary>>} ->
            {data, ttl, remainder}
        end

      {%Resolver.Answer{
         name: Enum.join(name, "."),
         type: type,
         class: 1,
         ttl: ttl,
         data: parsedData
       }, remainder}
    end
  end

  defmodule Name do
    def toBitstring(name) do
      encodedName =
        name
        |> String.split(".")
        |> Enum.map(fn namePart ->
          <<String.length(namePart), namePart::binary>>
        end)
        |> Enum.join("")

      encodedName <> <<0>>
    end

    def fromBitstring(body, nameRaw, accumulator \\ [])

    def fromBitstring(
          body,
          <<1::1, 1::1, pointer::14, remainder::binary>>,
          accumulator
        ) do
      IO.inspect(pointer, label: "dns compression pointer")
      <<_::binary-size(pointer - 12), nameRaw::binary>> = body
      {name, _} = fromBitstring(body, nameRaw)
      {accumulator ++ name, remainder}
    end

    def fromBitstring(
          _body,
          <<0::8, remainder::binary>>,
          accumulator
        ) do
      {accumulator, remainder}
    end

    def fromBitstring(
          body,
          <<len::8, domainParts::binary-size(len), remainder::binary>>,
          accumulator
        ) do
      IO.inspect(domainParts, label: "domainparts")
      IO.inspect(len, label: "domain part length")
      fromBitstring(body, remainder, accumulator ++ [domainParts])
    end
  end

  defmodule IP do
    def fromBitstring(bitstring) do
      octets =
        for <<octet::8 <- bitstring>> do
          octet
        end

      Enum.join(octets, ".")
    end
  end

  defp unpackDNSResponse(<<headerRaw::binary-size(12), body::binary>>) do
    IO.puts("unpacking header")
    header = Header.fromBitstring(headerRaw)

    IO.puts("unpacking question")
    {question, data} = Question.fromBitstring(body)

    IO.inspect(header, label: "header")

    # TODO: bug, enum is called multiple times even when header.num_answers is 0
    {answers, remainder} =
      if header.num_answers > 0 do
        Enum.reduce(1..header.num_answers, {[], data}, fn _, {answers, remainder} ->
          IO.puts("enumerating answer")
          {answer, remainder} = Answer.fromBitstring(body, remainder)
          {[answer | answers], remainder}
        end)
      else
        {nil, data}
      end

    {authorities, additionalsRaw} =
      if header.num_authorities > 0 do
        Enum.reduce(1..header.num_authorities, {[], remainder}, fn _, {answers, remainder} ->
          IO.puts("enumerating authorities")
          {answer, remainder} = Answer.fromBitstring(body, remainder)
          {[answer | answers], remainder}
        end)
      else
        {nil, remainder}
      end

    {additionals, _} =
      if header.num_additionals > 0 do
        Enum.reduce(1..header.num_additionals, {[], additionalsRaw}, fn _, {answers, remainder} ->
          IO.puts("enumerating additionals")
          {answer, remainder} = Answer.fromBitstring(body, remainder)
          {[answer | answers], remainder}
        end)
      else
        {nil, nil}
      end

    {header, question, answers, authorities, additionals}
  end

  defp buildQuery(name, recordType) do
    name = Name.toBitstring(name)
    id = :rand.uniform(65535)
    flags = <<0 <<< 8::16>>
    # flags = <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>
    header = Header.toBitstring(%Header{id: id, flags: flags, num_questions: 1})
    question = Question.toBitstring(%Question{name: name, type: recordType, class: 1})
    header <> question
  end

  def query(domain, resolver) do
    dnsPacket = buildQuery(domain, 1)
    {:ok, socket} = :gen_udp.open(0, [:binary, active: false])
    :ok = :gen_udp.send(socket, resolver, 53, dnsPacket)

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
