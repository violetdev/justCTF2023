
### ECC Not Only For Dummies - Misc Challenge

### Explaination

# The Python program takes code as input, validates and evaluates.
# By submitting the questions 'print(c[i])', where 'c' is the cards array (parsed in sandbox.py), and 'i' the index of cards, 'sandbox.py' will return value as 'None'.
# However, 'print(c[i])' will itself output 'c[i]' (either True/False) to stdout, this will tell us the cards array.
# There are 11 cards and 11 questions, but 3 random wrong answers, in which case the value will be either True/False and not 'None'.
# The initial wrong answers are sampled randomly, so will need to run ~9 times (1/9 probability that 3 random numbers will be in ascending order).

# Solution idea can also be applied to: ECC For Dummies (easier challenge)



from pwn import * 
import pow

# Connect to server, (possible to do it manually since only 11 questions, but server can timeout.)
conn = remote('eccnotonlyfordummies.nc.jctf.pro', 1337, ssl=False)
res = conn.recvline()
res = str(res)
print(res)

# Proof of Work
start = res.find('(')
end = res.find(' ')
prefix = res[(start+1):end]
challenge = 22
pow_init = pow.NcPowser(challenge)
i = 0
while not pow_init.verify_hash(prefix, str(i)):
    i += 1
print(i)
conn.sendline(str(i))

# Outputs
solution = []
wrong = []

# Send 'print(c[i])' and append to Ouput arrays
for i in range(11):
    print('Question:', i)
    conn.recvuntil(b'Question: ', timeout=10000)
    question = 'print(c[' + str(i) + '])'
    conn.sendline(question)
    res = conn.recvline()
    print(res)
    if res == b'True\n':
        solution.append('1')
    else:
        solution.append('0')
    res = conn.recvline()
    if res[-5:] != b'None\n':
        print('---Wrong Found---')
        wrong.append(str(i))

conn.recvuntil(b'Your response: ', timeout=10000)
solution = ' '.join(solution)
print('Sending...', solution)
conn.sendline(solution)
conn.recvuntil(b'Wrong responses: ', timeout=10000)
wrong = ' '.join(wrong)
print('Sending...', wrong)
conn.sendline(wrong)

res = conn.recvline()
print(res)
res = conn.recvline()
print(res)

conn.close()

# justCTF{S4nd_S0metim3s_It$_EvEn_$0lv4ble}
