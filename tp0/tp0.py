import socket
import struct


def send_token_request(server_address, student_id, nonce):
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
        print(f"Resposta recebida:{responde_d}")
        return response


def process_server_response(response):
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
    # Exibe os resultados
    print("Tipo de Mensagem:", message_type)
    print("ID do Estudante:", student_id)
    print("Nonce:", nonce)
    print("Token de Autenticação:", token)
    individual_token_validation(("150.164.213.243", 51001), student_id, nonce, token)
    return message_type, student_id, nonce, token


def individual_token_validation(server_address, student_id, nonce, token):
    # Certifique-se que o student_id tem 12 caracteres, preenchendo com espaços
    student_id = student_id.ljust(12)
    # Tipo de mensagem: 2 bytes, valor 1 (para o request)
    message_type = 1
    # Monta a mensagem (18 bytes: tipo, ID, nonce)
    # Formato de struct: H para um unsigned short (2 bytes), 12s para string de 12 bytes, I para unsigned int (4 bytes)
    request_format = ">H80s"
    message = struct.pack(
        request_format, message_type, bytes(student_id, encoding="ascii"), nonce, token
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
        print(f"Resposta recebida:{responde_d}")
        return response


def main():
    process_server_response(
        send_token_request(("150.164.213.243", 51001), "2019083765", 12345678)
    )

    # send_token_request(("150.164.213.243", 51001), "2019083765", 12345678)


if __name__ == "__main__":
    main()
