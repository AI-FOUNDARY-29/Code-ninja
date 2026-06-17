import cv2
import numpy as np
from tensorflow.keras.models import load_model


class DeepfakeDetector:

    def __init__(self, model_path="models/deepfake_model.h5"):
        try:
            self.model = load_model(model_path)
            print("Deepfake model loaded successfully")

        except:
            self.model = None
            print("Model not found. Running demo mode")


    def preprocess_image(self, image_path):

        img = cv2.imread(image_path)

        img = cv2.resize(img, (224,224))

        img = img / 255.0

        img = np.expand_dims(img, axis=0)

        return img


    def detect_image(self, image_path):

        image = self.preprocess_image(image_path)


        if self.model:

            prediction = self.model.predict(image)

            fake_probability = prediction[0][0]


        else:
            # Demo prediction
            fake_probability = np.random.random()



        if fake_probability > 0.5:

            result = "FAKE"

        else:

            result = "REAL"



        return {

            "type":"image",

            "prediction":result,

            "fake_probability":round(float(fake_probability),2),

            "risk_level":
                "HIGH" if fake_probability > 0.7
                else "LOW"

        }



    def detect_video(self, video_path):

        cap = cv2.VideoCapture(video_path)

        fake_scores=[]


        while True:

            ret,frame = cap.read()

            if not ret:
                break


            frame=cv2.resize(frame,(224,224))

            frame=frame/255.0

            frame=np.expand_dims(frame,axis=0)


            if self.model:

                score=self.model.predict(frame)[0][0]

            else:

                score=np.random.random()


            fake_scores.append(score)


        cap.release()


        average_score=np.mean(fake_scores)


        return {

            "type":"video",

            "prediction":
                "FAKE" if average_score>0.5 else "REAL",

            "fake_probability":
                round(float(average_score),2),

            "risk_level":
                "HIGH" if average_score>0.7 else "LOW"

        }
