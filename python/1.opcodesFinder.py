import pefile
import os
from capstone import *

# This code finds the 50 most frequent opcodes and saves them in a .csv file

# Reading the folders with the items for training
folders = ["exeBenigni/" + item for item in os.listdir("exeBenigni/")] + \
          ["exeMaligni/" + item for item in os.listdir("exeMaligni/")]

nItems = len(folders)  # Total number of items
opcodeSet = set()  # Set contanining every opcode found
opCodeFreq = {}  # Dictionary with every opcode found, key=opcode, value=number of occurrences

count = 1
for item in folders:
    try:
        # We have to find the entry point address for every item's assembly code with the PEfile package
        pe = pefile.PE(item, fast_load=True)
        entryPoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        data = pe.get_memory_mapped_image()[entryPoint:]  # We get the item's assembly code
        cs = Cs(CS_ARCH_X86, CS_MODE_32)  # Capstone instantiation

        opcodes = []
        # With capstone.disasm we get a collection of every assembly instruction
        for i in cs.disasm(data, 0x1000):
            opcodes.append(i.mnemonic)  # The instruction's opcode is in the mnemonic attribute

        # We add the found opcodes to the set
        # Sets in python are collections of unique items, so only new opcodes will be added to the set
        opcodeSet = set(list(opcodeSet) + opcodes)
        # We iterate through every opcode found across all items, then we check if that opcode was found
        # in the current item, and we count how many times it was found
        for opcode in opcodeSet:
            opCodeCount = 0
            for opCodeC in opcodes:
                if opcode == opCodeC:
                    opCodeCount += 1
            # Then we update every found opcode dictionary
            try:
                opCodeFreq[opcode] += opCodeCount
            except:
                opCodeFreq[opcode] = opCodeCount

        os.system("clear")
        print(str((count / nItems) * 100) + "%")  # Visualizing the progress
        count += 1
    except Exception as e:
        print(e)

# We sort the dictionary based on the frequency value
opCodeFreqSort = sorted(opCodeFreq, key=opCodeFreq.get)[-1:0:-1]

# We write the 50 most frequent opcodes found
with open("50opcodes.csv", "w") as f:
    f.write("opcode, frequency\n")
    for opcode in opCodeFreqSort[:50]:
        f.write(str(opcode) + ", " + str(opCodeFreq[opcode]) + "\n")
