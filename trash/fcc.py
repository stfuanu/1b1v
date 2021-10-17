import blocksmith

kg = blocksmith.KeyGenerator()

inp = input("Enter your value: ")
kg.seed_input(inp)
key = kg.generate_key()
print(key)
