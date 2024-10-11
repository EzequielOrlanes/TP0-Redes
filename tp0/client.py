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
    families = [socket.AF_INET6, socket.AF_INET]
    for family in families:
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.sendto(message, server_address)
                # Recebe a resposta do servidor
                response, _ = sock.recvfrom(1024)
                return response
        except socket.error as e:
            continue


def individual_token_response(response):
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
    families = [socket.AF_INET6, socket.AF_INET]
    for family in families:
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.sendto(message, server_address)
                # Recebe a resposta do servidor
                response, _ = sock.recvfrom(1024)
                return response
        except socket.error as e:
            print(f"Erro ao conectar-se usando {family}: {e}")
            continue


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
    print("Individual token status: ")
    print(message_type, student_id, nonce, token, status)
    print("________________________________________")
    return message_type, student_id, nonce, token, status


def group_token_request(server_address, sas_list):
    message_type = 5
    num_sas = len(sas_list)
    request_format = f">HH{80 * num_sas}s"
    sas_bytes = b"".join(sas_list)
    # Empacota a mensagem
    message = struct.pack(request_format, message_type, num_sas, sas_bytes)
    families = [socket.AF_INET6, socket.AF_INET]
    for family in families:
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.sendto(message, server_address)
                # Recebe a resposta do servidor
                response, _ = sock.recvfrom(1024)
                return response
        except socket.error as e:
            continue


def group_token_response(response, num_sas):
    response_format = f">HH{80 * num_sas}s64s"
    # Desempacota a resposta conforme o formato correto
    message_type, num_sas_, sas_bytes, token = struct.unpack(response_format, response)
    # sas = sas.decode("ascii")
    # Exibe os resultados
    # Decodifica o token (a string hexadecimal de 64 bytes)
    token = token.decode("ascii")
    print("*************1**************")
    print(message_type, num_sas_, sas_bytes, token)
    print("**************1*************")
    tamanho_em_bytes = len(response)
    print("O tamanho da resposta group token request em bytes é:", tamanho_em_bytes)
    return message_type, num_sas_, sas_bytes, token


def group_token_validation(server_address, message_type, num_sas_, sas_bytes, token):
    message_type = 7
    request_format = f">HH{80 * num_sas_}s64s"
    token = token.encode("utf-8")
    message = struct.pack(request_format, message_type, num_sas_, sas_bytes, token)
    # Cria o socket UDP e envia a mensagem para o servidor
    families = [socket.AF_INET6, socket.AF_INET]
    for family in families:
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.sendto(message, server_address)
                # Recebe a resposta do servidor
                response, _ = sock.recvfrom(1024)
                return response
        except socket.error as e:
            continue


def group_token_status(response, num_sas):
    response_format = f">HH{80 * num_sas}s64s1s"
    message_type, num_sas_, sas_bytes, token, s = struct.unpack(
        response_format, response
    )
    token = token.decode("ascii")
    print("***************************")
    print(message_type, num_sas_, sas_bytes, token, s)
    print("***************************")
    tamanho_em_bytes = len(response)
    print("O tamanho da resposta group token request em bytes é:", tamanho_em_bytes)


def convert_sas_to_bytes(sas_list):
    sas_bytes_list = []
    for sas in sas_list:
        # Pegamos os valores do SAS
        student_id = sas["student_id"]
        nonce = sas["nonce"]
        token = sas["token"]
        # Certifique-se de que o student_id tem exatamente 12 bytes
        student_id_bytes = student_id.ljust(12).encode("ascii")
        # Certifique-se de que o token tem exatamente 64 bytes
        token_bytes = token.ljust(64).encode("ascii")
        # Empacotar os dados (formato: 12s para student_id, I para nonce, 64s para token)
        sas_format = ">12sI64s"
        sas_bytes = struct.pack(sas_format, student_id_bytes, nonce, token_bytes)
        # Adicionar à lista de SAS em bytes
        sas_bytes_list.append(sas_bytes)

    return sas_bytes_list


def main():
    while True:
        command_line = input(
            "Digite o comando (e.g., itr <id> <nonce>, ou 'sair' para encerrar):"
        )
        parts = command_line.split(" ")
        if command_line and len(parts) >= 3:
            host = parts[0]
            port = int(parts[1])  # Converter porta para inteiro
            command = parts[2]
            args = parts[-1]
            args_ = args.split(" ")
            if command == "itr":
                message_type, student_id, nonce, token = individual_token_response(
                    individual_token_request((host, port), str(args_[0]), args_[1])
                )
            print("individual token response:")
            print(message_type, student_id, nonce, token)
        # elif command == "gtr":

    # individual_token_status(
    #     individual_token_validation(
    #         ("150.164.213.243", 51001), student_id, nonce, token
    #     )
    # )
    # sas_list = []
    # sas1 = {"student_id": student_id, "nonce": nonce, "token": token}
    # sas_list.append(sas1)
    # sas2 = {"student_id": student_id, "nonce": nonce, "token": token}
    # sas_list.append(sas2)
    # print(sas_list)

    # message_type_g, num_sas_g, sas_bytes_g, token_g = group_token_response(
    #     group_token_request(("150.164.213.243", 51001), convert_sas_to_bytes(sas_list)),
    #     len(sas_list),
    # )
    # group_token_status(
    #     group_token_validation(
    #         ("150.164.213.243", 51001), message_type_g, num_sas_g, sas_bytes_g, token_g
    #     ),
    #     len(sas_list),
    # )


if __name__ == "__main__":
    main()
