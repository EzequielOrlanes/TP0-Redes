import socket
import struct


def individual_token_request(server_address, student_id, nonce):
    # Certifique-se que o student_id tem 12 caracteres, preenchendo com espaços
    student_id = student_id.ljust(12)
    # Tipo de mensagem: 2 bytes, valor 1 (para o request)
    message_type = 1
    # Monta a mensagem (18 bytes: tipo, ID, nonce)
    # Formato de struct: H para um unsigned short (2 bytes), 12s para string de 12 bytes, I para unsigned int (4 bytes)
    request_format = ">H12sI"
    message = struct.pack(
        request_format, message_type, bytes(student_id, encoding="ascii"), nonce
    )
    # Cria o socket UDP e envia a mensagem para o servidor
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(message, server_address)
        # print(f"Mensagem enviada: {message}")
        # for byte in message:
        #     print(hex(byte), end=" ")
        # Recebe a resposta do servidor
        response, _ = sock.recvfrom(1024)
        responde_d = response.decode("utf-8", errors="ignore")
        tamanho_em_bytes = len(response)
        print("O tamanho da resposta em bytes é:", tamanho_em_bytes)
        print(f"Resposta recebida:{responde_d}")
        return response


def individual_token_response(response):
    print(
        "____________________________Individual Token Response_____________________________________________"
    )
    # Formato ajustado: "H12sI64s", totalizando 82 bytes
    response_format = ">H12sI64s"
    # Certifique-se de que a resposta tem exatamente 82 bytes
    if len(response) != 82:
        raise ValueError(
            f"Resposta inválida, esperado 80 bytes, recebido {len(response)} bytes"
        )
    # Desempacota a resposta conforme o formato correto
    message_type, student_id, nonce, token = struct.unpack(response_format, response)
    # Decodifica o ID do estudante (removendo espaços extras)
    student_id = student_id.decode("ascii").strip()
    # Decodifica o token (a string hexadecimal de 64 bytes)
    token = token.decode("ascii")
    # group_token_request(("150.164.213.243", 51001), student_id, nonce, token)
    return message_type, student_id, nonce, token


def individual_token_validation(server_address, student_id, nonce, token):
    # Certifique-se que o student_id tem 12 caracteres, preenchendo com espaços
    student_id = student_id.ljust(12)
    # Tipo de mensagem: 2 bytes, valor 1 (para o request)
    message_type = 3
    # Monta a mensagem (18 bytes: tipo, ID, nonce)
    # encode token para ser estar bytes
    token_e = token.encode("utf-8")
    # Formato de struct: H para um unsigned short (2 bytes), 12s para string de 12 bytes, I para unsigned int (4 bytes), 64s para 64 bytes.
    request_format = ">H12sI64s"
    message = struct.pack(
        request_format,
        message_type,
        bytes(student_id, encoding="ascii"),
        nonce,
        token_e,
    )
    # Cria o socket UDP e envia a mensagem para o servidor
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(message, server_address)
        # Recebe a resposta do servidor
        response, _ = sock.recvfrom(1024)
        return response


def individual_token_status(response):
    response_format = ">H12sI64sB"
    # Certifique-se de que a resposta tem exatamente 82 bytes
    if len(response) != 83:
        raise ValueError(
            f"Resposta inválida, esperado 83 bytes, recebido {len(response)} bytes"
        )
    # Desempacota a resposta conforme o formato correto
    message_type, student_id, nonce, token, status = struct.unpack(
        response_format, response
    )
    if message_type != 4:
        raise ValueError(
            f"Resposta inválida, esperado 4 como message type, recebido {message_type} bytes"
        )
    # Decodifica o ID do estudante (removendo espaços extras)
    student_id = student_id.decode("ascii").strip()
    # Decodifica o token (a string hexadecimal de 64 bytes)
    token = token.decode("ascii")
    # group_token_request(("150.164.213.243", 51001), student_id, nonce, token)
    print("Individual token status: ")
    print(message_type, student_id, nonce, token, status)
    return message_type, student_id, nonce, token, status


def group_token_request(server_address, sas_list):
    # Certifique-se que o student_id tem 12 caracteres, preenchendo com espaços
    student_id = sas_list[0]["student_id"].ljust(12)
    # Tipo de mensagem: 2 bytes, valor 1 (para o request)
    message_type = 5
    if len(sas_list) < 1 and len(sas_list) > 16:
        return 0
    # Monta a mensagem (18 bytes: tipo, ID, nonce)
    # encode token para ser estar bytes
    num_sas = len(sas_list)
    token_e = sas_list[0]["token"].encode("utf-8")
    nonce = sas_list[0]["nonce"]
    # Formato de struct: H para um unsigned short (2 bytes),  H para um unsigned short (2 bytes),  12s para string de 12 bytes, I para unsigned int (4 bytes), 64s para 64 bytes.
    request_format = ">2H12sI64s"
    message = struct.pack(
        request_format,
        message_type,
        num_sas,
        bytes(student_id, encoding="ascii"),
        nonce,
        token_e,
    )
    # Cria o socket UDP e envia a mensagem para o servidor
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(message, server_address)
        # Recebe a resposta do servidor
        response, _ = sock.recvfrom(1024)
        responde_d = response.decode("utf-8", errors="ignore")
        tamanho_em_bytes = len(response)
        print("O tamanho da resposta em bytes é:", tamanho_em_bytes)
        print(f"Resposta recebida ----->>>:{responde_d}")
        # responde_d = response.decode("utf-8", errors="ignore")
        return response


def group_token_response(response):
    # Formato ajustado: "H12sI64s", totalizando 82 bytes
    response_format = ">2H12sI64s"
    # Certifique-se de que a resposta tem exatamente 82 bytes
    if len(response) != 148:
        raise ValueError(
            f"Resposta inválida, esperado 148 bytes, recebido {len(response)} bytes"
        )
    # Desempacota a resposta conforme o formato correto
    message_type, num_sas, sas = struct.unpack(response_format, response)
    # Decodifica o ID do estudante (removendo espaços extras)
    student_id = student_id.decode("ascii").strip()
    # Decodifica o token (a string hexadecimal de 64 bytes)
    token = token.decode("ascii")
    # Exibe os resultados
    print(message_type, student_id, nonce, token)
    tamanho_em_bytes = len(response)
    print("O tamanho da resposta group token request em bytes é:", tamanho_em_bytes)
    # token_group = response[84:]
    print("O token da resposta é:", token_group)
    print(f"Resposta recebida de status:{responde_d}")
    # group_token_validation(
    #     ("150.164.213.243", 51001), student_id, nonce, token_group
    # )


def group_token_validation(server_address, student_id, nonce, token):
    print(
        "____________________________Group token Validation________________________________________________"
    )
    # Certifique-se que o student_id tem 12 caracteres, preenchendo com espaços
    student_id = student_id.ljust(12)
    # Tipo de mensagem: 2 bytes, valor 1 (para o request)
    message_type = 7
    num_sas = 1
    if num_sas < 1 and num_sas > 16:
        return 0
    # Monta a mensagem (18 bytes: tipo, ID, nonce)
    # encode token para ser estar bytes
    token_e = token.decode("utf-8")
    # Formato de struct: H para um unsigned short (2 bytes),  H para um unsigned short (2 bytes),  12s para string de 12 bytes, I para unsigned int (4 bytes), 64s para 64 bytes.
    request_format = ">2H12sI64s"
    response_format = ">H12sI64sH"
    message = struct.pack(
        request_format,
        message_type,
        num_sas,
        bytes(student_id, encoding="ascii"),
        nonce,
        token_e,
    )
    # Cria o socket UDP e envia a mensagem para o servidor
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(message, server_address)
        # Recebe a resposta do servidor
        response, _ = sock.recvfrom(1024)
        responde_d = response.decode("utf-8", errors="ignore")
        message_type, num_sass, student_id, nonce, token, status = struct.unpack(
            response_format, response
        )
        # Decodifica o ID do estudante (removendo espaços extras)
        student_id = student_id.decode("ascii").strip()
        # Decodifica o token (a string hexadecimal de 64 bytes)
        token = token.decode("ascii")
        # Exibe os resultados
        print(message_type, student_id, nonce, token)
        tamanho_em_bytes = len(response)
        print("O tamanho da resposta group token request em bytes é:", tamanho_em_bytes)
        status = response[-1]
        print("O token da resposta é:", status)
        print(f"Resposta recebida de status:{responde_d}")
        return response


def main():
    message_type, student_id, nonce, token = individual_token_response(
        individual_token_request(("150.164.213.243", 51001), "2019083765", 12345678)
    )
    print("individual token response:")
    print(message_type, student_id, nonce, token)
    print("________________________________________________________")
    individual_token_status(
        individual_token_validation(
            ("150.164.213.243", 51001), student_id, nonce, token
        )
    )

    sas_list = []
    sas1 = {"student_id": student_id, "nonce": nonce, "token": token}
    sas_list.append(sas1)
    # sas2 = {"student_id": student_id, "nonce": nonce, "token": token}
    # sas_list.append(sas2)
    print(sas_list)
    # group_token_response(
    group_token_request(("150.164.213.243", 51001), sas_list)
    # )


if __name__ == "__main__":
    main()
