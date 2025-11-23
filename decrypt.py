import sys
import base64
import string

secret_encoding = ['step1', 'step2', 'step3']

_step1_src = "zyxwvutsrqponZYXWVUTSRQPONmlkjihgfedcbaMLKJIHGFEDCBAzyxwvutsrqponZYXWVUTSRQPON"
_step1_dst = "mlkjihgfedcbaMLKJIHGFEDCBAzyxwvutsrqponZYXWVUTSRQPON"

def _make_trans_dict(src, dst):
    m = {}
    for a, b in zip(src, dst):
        m[ord(a)] = ord(b)
    return m

def step1(s):
    table = _make_trans_dict(_step1_src, _step1_dst)
    return s.translate(table)

def inv_step1(s):
    table = _make_trans_dict(_step1_dst, _step1_src)
    return s.translate(table)

def step2(s):
    return base64.b64encode(s.encode('utf-8')).decode('utf-8')

def inv_step2(s):
    return base64.b64decode(s.encode('utf-8')).decode('utf-8')

def step3(plaintext, shift=4):
    loweralpha = string.ascii_lowercase
    shifted_string = loweralpha[shift:] + loweralpha[:shift]
    table = str.maketrans(loweralpha, shifted_string)
    return plaintext.translate(table)

def inv_step3(ciphertext, shift=4):
    loweralpha = string.ascii_lowercase
    shifted_string = loweralpha[shift:] + loweralpha[:shift]
    table = str.maketrans(shifted_string, loweralpha)
    return ciphertext.translate(table)

def decrypt(ciphertext):
    s = ciphertext
    while s and s[0] in '123':
        idx = s[0]
        s = s[1:]
        if idx == '1':
            s = inv_step1(s)
        elif idx == '2':
            s = inv_step2(s)
        elif idx == '3':
            s = inv_step3(s)

    if not s:
        raise ValueError('Empty payload after peeling steps')
    if s[0] != '2':
        return s

    b64part = s[1:]
    try:
        plain = base64.b64decode(b64part.encode('utf-8')).decode('utf-8')
    except Exception as e:
        raise ValueError('Final payload is not valid base64: {}'.format(e))
    return plain

def main():
    print('Paste the intercepted ciphertext (single line), then press Enter:')
    try:
        ct = sys.stdin.readline().strip()
    except KeyboardInterrupt:
        return
    if not ct:
        print('No ciphertext provided')
        return
    try:
        plain = decrypt(ct)
    except Exception as e:
        print('Failed to decrypt: {}'.format(e))
        return
    print('\nRecovered plaintext:\n{}'.format(plain))

if __name__ == '__main__':
    main()
