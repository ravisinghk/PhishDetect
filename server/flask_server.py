from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle

# Load the model
with open('model.sav', 'rb') as f:
    model = pickle.load(f)

app = Flask(__name__)
CORS(app)


@app.route('/predict', methods=['POST'])
def predict():
    # Get the data from the request
    data = request.get_json().reshape(1, -1)

    # Use the model to make predictions
    predictions = model.predict(data)

    l = [predictions.tolist()]

    print(l)
    # Return the predictions as a JSON object
    return jsonify(l)


if __name__ == '__main__':
    app.run(port=8000)
