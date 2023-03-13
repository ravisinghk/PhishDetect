from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import numpy as np

# Load the model
with open('model.sav', 'rb') as f:
    model = pickle.load(f)

app = Flask(__name__)
CORS(app)


@app.route('/predict', methods=['POST'])
def predict():
    print("Hello")
    data = request.get_json(force=True)
    print(type(data))
    prediction = model.predict([np.array(data)])
    output = prediction[0]
    print(output)
    output_json = {'prediction': str(output)}  # convert to str
    # return jsonify(output_json)
    return output_json


if __name__ == '__main__':
    app.run(port=8000)
