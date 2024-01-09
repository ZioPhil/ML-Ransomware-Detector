import numpy as np
import pefile
import os
from capstone import *

# This code produces a vector for every training item, that will be used as input for the ML model training
# In every vector we find the probability of occurrence of the top 50 opcodes for a certain item

# Most of the code below is the same as the one in 1.opcodesFinder.py, so I will comment
# only the differences

benigniFolder = ["exeBenigni/" + item for item in os.listdir("exeBenigni/")]
maligniFolder = ["exeMaligni/" + item for item in os.listdir("exeMaligni/")]

nItems = len(benigniFolder) + len(maligniFolder)
opCodeBenigniSet = set()
opCodeBenigniFreq = {}
# The purpose of this list of dictionaries is to count the number of occurrences of the found opcodes
# for every item, so we have a dictionary for every item
opCodeBenigniDictList = []

count = 1
for item in benigniFolder:
    try:
        pe = pefile.PE(item, fast_load=True)
        entryPoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        data = pe.get_memory_mapped_image()[entryPoint:]
        cs = Cs(CS_ARCH_X86, CS_MODE_32)

        opcodes = []
        for i in cs.disasm(data, 0x1000):
            opcodes.append(i.mnemonic)

        opcodeDict = {}  # We instantiate the dictionary for the current item
        n = len(opcodes)

        opCodeBenigniSet = set(list(opCodeBenigniSet) + opcodes)
        for opcode in opCodeBenigniSet:
            opCodeCount = 0
            for opCodeC in opcodes:
                if opcode == opCodeC:
                    opCodeCount += 1
            try:
                opCodeBenigniFreq[opcode] += opCodeCount
            except:
                opCodeBenigniFreq[opcode] = opCodeCount

            # In this dictionary we have the probability of occurrence of every found opcode for the
            # current item
            # This dictionary is very close to the final data that we want to achieve, the only difference
            # is that we will filter it to include only the 50 most used opcodes
            opcodeDict[opcode] = round((opCodeCount / n) * 100, 2)

        opCodeBenigniDictList.append(opcodeDict)  # We save the dictionary in the list

        os.system("clear")
        print(str((count / nItems) * 100) + "%")
        count += 1

    except Exception as e:
        print(e)

# We do the same thing as before, this time with the ransomwares
opCodeMaligniSet = set()
opCodeMaligniFreq = {}
opCodeMaligniDictList = []

count = len(benigniFolder)
for item in maligniFolder:
    try:
        pe = pefile.PE(item, fast_load=True)
        entryPoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        data = pe.get_memory_mapped_image()[entryPoint:]
        cs = Cs(CS_ARCH_X86, CS_MODE_32)

        opcodes = []
        for i in cs.disasm(data, 0x1000):
            opcodes.append(i.mnemonic)

        opcodeDict = {}
        n = len(opcodes)

        opCodeMaligniSet = set(list(opCodeMaligniSet) + opcodes)
        for opcode in opCodeMaligniSet:
            opCodeCount = 1
            for opCodeC in opcodes:
                if opcode == opCodeC:
                    opCodeCount += 1
            try:
                opCodeMaligniFreq[opcode] += opCodeCount
            except:
                opCodeMaligniFreq[opcode] = opCodeCount

            opcodeDict[opcode] = round((opCodeCount / n) * 100, 2)

        opCodeMaligniDictList.append(opcodeDict)

        os.system("clear")
        print(str((count / nItems) * 100) + "%")
        count += 1

    except Exception as e:
        print(e)

# We get the 50 most used opcodes from the file
opCodeFreqSort = np.genfromtxt("50opcodes.csv", delimiter=",", dtype="str")[1:, 0]

# Now we have to extract the probability of occurrence of the 50 most used opcodes for every item
count = 0
for opCodeDict in opCodeBenigniDictList:
    opProbVec = []  # This is the final data that will be used in the training process
    for opcode in opCodeFreqSort[:50]:
        try:
            opProbVec.append(opCodeDict[opcode])
        except Exception as e:
            if str(type(e)) == "<class 'KeyError'>":
                opProbVec.append(0.0)

    # We save the result in a npy file for every item
    np.save("vecBenigni/" + str(count) + ".npy", opProbVec)
    os.system("clear")
    print(str((count / nItems) * 100) + "%")
    count += 1

# We do the same for the ransomwares
count = len(benigniFolder)
for opCodeDict in opCodeMaligniDictList:
    opProbVec = []
    for opcode in opCodeFreqSort[:50]:
        try:
            opProbVec.append(opCodeDict[opcode])
        except Exception as e:
            if str(type(e)) == "<class 'KeyError'>":
                opProbVec.append(0.0)

    np.save("vecMaligni/" + str(count) + ".npy", opProbVec)
    os.system("clear")
    print(str((count / nItems) * 100) + "%")
    count += 1
