from cryptolib.misc.two_time_pad import decrypt_two_time_pad

lemur_filename = "lemur.png"
flag_filename = "flag.png"

with open(lemur_filename, 'rb') as f:
    lemur_bytes = f.read()
with open(flag_filename, 'rb') as f:
    flag_bytes = f.read()

decrypt_two_time_pad([lemur_bytes, flag_bytes])