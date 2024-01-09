import sys
import pefile
import numpy as np
from capstone import *
from tensorflow.python.keras.models import Sequential
from tensorflow.python.keras import layers

# Recovering the model, as we did in 4.modelTester.py
model = Sequential()
model.add(layers.InputLayer(input_shape=(50,)))
model.add(layers.Dense(128, activation='relu'))
model.add(layers.Dropout(0.2))
model.add(layers.Dense(64, activation='relu'))
model.add(layers.Dense(32, activation='relu'))
model.add(layers.Dense(16, activation='relu'))
model.add(layers.Dense(2, activation='softmax'))
# If you execute the java program the working directory is not "python" but the parent directory
# If you want to execute this file alone, you will have to remove "python" from the path below
model.load_weights("python/weights/weights-405-1.00.hdf5")
model.compile(optimizer="rmsprop", loss='categorical_crossentropy', metrics=['accuracy'])


# This functions takes a list of paths to exe files and produces the vectors for these files, the same
# way we did in 2.vectorGenerator.py with the training items. The code will be the same, so
# I will comment only the differences
# The vectors will be used as input for the model
def vec_generation(paths):
    vecs = []

    opcode_set = set()
    opcode_freq = {}
    opcode_dict_list = []

    count = 1
    for item in paths:
        try:
            pe = pefile.PE(item, fast_load=True)
            entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            data = pe.get_memory_mapped_image()[entry_point:]
            cs = Cs(CS_ARCH_X86, CS_MODE_32)

            opcodes = []
            for i in cs.disasm(data, 0x1000):
                opcodes.append(i.mnemonic)

            opcode_dict = {}
            n = len(opcodes)

            opcode_set = set(list(opcode_set) + opcodes)
            for opcode in opcode_set:
                opcode_count = 0
                for opcode_c in opcodes:
                    if opcode == opcode_c:
                        opcode_count += 1
                try:
                    opcode_freq[opcode] += opcode_count
                except:
                    opcode_freq[opcode] = opcode_count

                opcode_dict[opcode] = round((opcode_count / n) * 100, 2)

            opcode_dict_list.append(opcode_dict)
            count += 1

        except Exception as e:
            # If this exception is thrown, it means that the current item is not a valid PE file
            # This means that the file is not a PE file, or that it's a faulty one(that could never
            # get executed anyway)

            # So we create a dictionary that allows us to recognize this file in further elaborations, and we
            # add it to the list
            empty_dict = {"fileNotValid", 422.00}
            opcode_dict_list.append(empty_dict)
            count += 1

    # If you execute the java program the working directory is not "python" but the parent directory
    # If you want to execute this file alone, you will have to remove "python" from the path below
    opcode_freq_sort = np.genfromtxt("python/50opcodes.csv", delimiter=",", dtype="str")[1:, 0]

    count = 1
    for opcode_dict in opcode_dict_list:
        op_prob_vec = []

        # We check if the current file it's a faulty one: in that case, we add invalid values to the list
        # We are using percentages so every value above 100 is invalid
        if "fileNotValid" in opcode_dict:
            for i in range(50):  # The list must have 50 elements anyway
                op_prob_vec.append(422.00)
        else:
            for opcode in opcode_freq_sort[:50]:
                try:
                    op_prob_vec.append(opcode_dict[opcode])
                except Exception as e:
                    if str(type(e)) == "<class 'KeyError'>":
                        op_prob_vec.append(0.0)

        vecs.append([np.array(op_prob_vec)])
        count += 1

    vecs = np.array(vecs)
    return vecs


# Function to predict the input items classes
def prediction(paths):
    classes = ["benign", "ransomware"]
    predictions = {}

    count = 0
    # We generate the vector for every file, then we predict the class
    for path in paths:
        vector = vec_generation(paths)[count]
        count += 1

        # We know that the file isn't valid if it produces a vector full of invalid values
        if vector[0][0] == 422.00:
            predictions[path] = "fileNotValid"
        else:
            predictions[path] = classes[np.argmax(model.predict(x=vector))]

    return predictions


if __name__ == "__main__":
    try:
        # We get the file's paths from the arguments, and we remove the first argument(executed file name)
        paths = sys.argv
        paths.pop(0)

        # Then we predict the class of every file and we print the results on console
        preds = prediction(paths)
        if len(preds) > 0:
            for filename in preds.keys():
                if preds[filename] == "fileNotValid":
                    print("'" + filename + "'" + " is not a valid PE file")
                else:
                    print("'" + filename + "'" + " detected as " + preds[filename])
        else:
            quit()
    except Exception as e:
        print(e)
