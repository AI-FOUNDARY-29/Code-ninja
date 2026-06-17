from deepfake_detector import DeepfakeDetector


# Initialize AI security agent

aegis_ai = DeepfakeDetector()



# User uploads suspicious image

result = aegis_ai.detect_image(
    "sample.jpg"
)


print(result)
