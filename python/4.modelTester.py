import os
import math
import numpy as np
from tensorflow.keras.models import Sequential
from tensorflow.python.keras import layers
from tensorflow.keras.utils import Sequence
from tensorflow.keras.utils import to_categorical
from sklearn.utils import shuffle

# This code tests the model accuracy
# Most of the code is the same as in 3.modelTrainer.py, so I will comment only the differences

vecBenigni = ["vecBenigni/" + fileName for fileName in os.listdir("vecBenigni")]
vecMaligni = ["vecMaligni/" + fileName for fileName in os.listdir("vecMaligni")]

nBenigni = len(vecBenigni)
nMaligni = len(vecMaligni)

x = np.array(vecBenigni + vecMaligni)
y = np.ones(nBenigni + nMaligni)
y[0:nBenigni] = 0
y[nBenigni:nBenigni + nMaligni] = 1

y = to_categorical(y, num_classes=2)

testInds = np.load("testInds.npy")

x_test = x[testInds]
y_test = y[testInds]


class TestSequence(Sequence):
    def __init__(self, x, y, batch_size):
        self.x, self.y = shuffle(x, y)
        self.batch_size = batch_size

    def __len__(self):
        return math.ceil(len(self.x) / self.batch_size)

    def __getitem__(self, idx):
        batch_x = self.x[idx * self.batch_size:(idx + 1) * self.batch_size]
        batch_y = self.y[idx * self.batch_size:(idx + 1) * self.batch_size]

        return np.array([
            np.load(file_name)
            for file_name in batch_x]), np.array(batch_y)

    def on_epoch_end(self):
        pass


batch_size = 1000
testSeqGen = TestSequence(x_test, y_test, batch_size)

model = Sequential()
model.add(layers.InputLayer(input_shape=(50,)))
model.add(layers.Dense(128, activation='relu'))
model.add(layers.Dropout(0.2))
model.add(layers.Dense(64, activation='relu'))
model.add(layers.Dense(32, activation='relu'))
model.add(layers.Dense(16, activation='relu'))
model.add(layers.Dense(2, activation='softmax'))
model.build(input_shape=(1, 50))

# We load the weights that led to the best validation accuracy during training
model.load_weights("weights/weights-405-1.00.hdf5")

model.compile(optimizer="rmsprop", loss='categorical_crossentropy', metrics=['accuracy'])

# We test the model
results = model.evaluate(x=testSeqGen,
                         verbose=1,
                         steps=len(testSeqGen),
                         workers=8,
                         use_multiprocessing=True)

print("test loss, test accuracy:", results)

# NOTE: Measured accuracy on the test set: 99.595%
