defmodule Resolver do
  import Bitwise
  require Logger

  @moduledoc """
  This module implements a very limited toy DNS resolver. It is capable of performing a recursive request to a single hardcoded nameserver

  Do not use this in production, it is vulnerable to DoS attacks on recursion and does not handle errors well.
  """

  # This hardcodes the first server to begin the recursive query from.
  @domainRoot {198, 41, 0, 4}

  defmodule Header do
    @moduledoc """
    This submodule implements decoding and encoding DNS packet headers.

    Headers are structured as a 2 byte query ID, 2 bytes of flags, then 8 bytes of 2-byte integers for the number of questions, answers, authorities and additionals included in the body of the packet.
    """
    defstruct id: nil,
              flags: nil,
              num_questions: 0,
              num_answers: 0,
              num_authorities: 0,
              num_additionals: 0

    @doc """
    Accepts a `Header` struct and returns a corresponding bitstring.
    """
    def toBitstring(%Header{} = header) do
      <<header.id::16, header.flags::binary, header.num_questions::16, header.num_answers::16,
        header.num_authorities::16, header.num_additionals::16>>
    end

    @doc """
    Accepts a correctly formatted bitstring and returns a new `Header`.
    """
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
    @moduledoc """
    This module implements decoding and encoding DNS Question packet segments. It decodes the name via the Name module.

    Questiosn are structured as a 2-byte integer for type, 2-byte integer for class and the remainder is an encoded name.
    """
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

      <<type::16, remainder::binary>> = remainder

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

          {_, <<1::16, ttl::32, len::16, data::binary-size(len), remainder::binary>>} ->
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
      fromBitstring(body, remainder, accumulator ++ [domainParts])
    end
  end

  defmodule IP do
    def fromBitstring(bitstring) do
      octets =
        for <<octet::8 <- bitstring>> do
          octet
        end

      List.to_tuple(octets)
    end

    def prettyPrint(ip) do
      ip |> Tuple.to_list() |> Enum.join(".")
    end
  end

  defp unpackDNSResponse(<<headerRaw::binary-size(12), body::binary>>) do
    header = Header.fromBitstring(headerRaw)

    {question, data} = Question.fromBitstring(body)

    {answers, remainder} =
      if header.num_answers > 0 do
        Enum.reduce(1..header.num_answers, {[], data}, fn _, {answers, remainder} ->
          {answer, remainder} = Answer.fromBitstring(body, remainder)
          {[answer | answers], remainder}
        end)
      else
        {nil, data}
      end

    {authorities, additionalsRaw} =
      if header.num_authorities > 0 do
        Enum.reduce(1..header.num_authorities, {[], remainder}, fn _, {answers, remainder} ->
          {answer, answerRaw} = Answer.fromBitstring(body, remainder)
          {[answer | answers], answerRaw}
        end)
      else
        {nil, remainder}
      end

    {additionals, _} =
      if header.num_additionals > 0 do
        Enum.reduce(1..header.num_additionals, {[], additionalsRaw}, fn _, {answers, remainder} ->
          {answer, remainder} = Answer.fromBitstring(body, remainder)
          {[answer | answers], remainder}
        end)
      else
        {nil, nil}
      end

    {:ok, {header, question, answers, authorities, additionals}}
  end

  defp buildQuery(name, recordType) do
    name = Name.toBitstring(name)
    id = :rand.uniform(65535)
    flags = <<0 <<< 8::16>>
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

  def recursiveQuery(domain, nameserver \\ @domainRoot) do
    Logger.info("Querying #{IP.prettyPrint(nameserver)} for #{domain}")
    {:ok, data} = query(domain, nameserver)

    case data do
      {_header, _question, answers, _, _} when answers != nil ->
        Logger.info("Answer(s) found: #{inspect(answers)}")

        {:ok, answers}

      {_header, _question, _answers, authorities, additionals} when authorities != nil ->
        Logger.info("Answers are nil, using authority or additional")

        if additionals != nil do
          # Filter out IPv6 additionals and pick first result
          nameserver = Enum.filter(additionals, fn x -> 1 == x.type end) |> Enum.at(0)

          Logger.info(
            "Using #{nameserver.name} (#{IP.prettyPrint(nameserver.data)}) from additionals"
          )

          # Recurse with 
          recursiveQuery(domain, nameserver.data)
        else
          authority = Enum.at(authorities, 0)
          Logger.info("Additionals are empty, looking up authority")
          {:ok, results} = recursiveQuery(authority.data)
          nameserver = Enum.at(results, 0)
          Logger.info("Found authority: #{IP.prettyPrint(nameserver.data)}")
          recursiveQuery(domain, nameserver.data)
        end

      _ ->
        {:unknownrecursion}
    end
  end
end
