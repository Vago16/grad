#uses CLIP model from huggingface (https://huggingface.co/docs/transformers/en/model_doc/clip?usage=Pipeline)

import pandas as pd
import torch
import torch.nn.functional as F
from transformers import CLIPProcessor, CLIPModel
from PIL import Image
from tqdm import tqdm
import os
from time import time

#move model to GPU if available, since I have laptop it is run on CPU
device = "cuda" if torch.cuda.is_available() else "cpu"
dtype = torch.float16 if device == "cuda" else torch.float32

#load CLIP model and processor
model_name = "openai/clip-vit-base-patch16"
model = CLIPModel.from_pretrained(model_name, torch_dtype=dtype, use_safetensors=True)
processor = CLIPProcessor.from_pretrained(model_name)
model.to(device)
#checkpoint for model loading
print("Loaded CLIP model...")

#top 3 predictions variable
top_ins = 3

#load csv file with image-instruction pairs
csv_file = "paired_ds.csv"
df = pd.read_csv("paired_ds.csv")
image_paths = df["image_path"].tolist() #for images
instructions = df["instruction"].tolist()   #for instructions

#encode text instructions
text_inputs = processor(
    text=instructions,
    padding=True,
    truncation=True,
    return_tensors="pt"
).to(device)

with torch.no_grad():
    text_features = model.get_text_features(**text_inputs)

#normalize text features
text_features = F.normalize(text_features, p=2, dim=1)

#checkpoint for text encoding
print("Encoded text instructions...")

#initialize list for image features
image_features_list = []
#normalize images
for path in tqdm(image_paths, desc="Images"):
    image = Image.open(path).convert("RGB")
    inputs = processor(images=image, return_tensors="pt").to(device)
    with torch.no_grad():
        img_feat = model.get_image_features(**inputs)
    img_feat = F.normalize(img_feat, p=2, dim=1)
    image_features_list.append(img_feat)

image_features = torch.cat(image_features_list, dim=0)

#checkpoint for image encoding
print("Encoded images...")

similarity = image_features @ text_features.T
top1 = similarity.argmax(dim=1)

correct = sum(i == j for i, j in enumerate(top1))
accuracy = correct / len(image_paths)
print(f"Retrieval Accuracy: {accuracy * 100:.2f}%")

#5 qualitative examples with input images + model outputs
print("\n\tFive qualitative examples")
for i in range(min(5, len(image_paths))):
    topk = similarity[i].topk(top_ins)
    top_texts = [instructions[idx] for idx in topk.indices.cpu().numpy()]
    print(f"Image-instruction pair {i+1}")
    print(f"Image: {image_paths[i]}")
    print(f"True Instruction: {instructions[i]}")
    print(f"Top Prediction: {top_texts[0]}")
    print(f"Top-{top_ins} Predictions: {top_texts}")
    print()

#save the results to a csv file
results = []
for i in range(len(image_paths)):
    topk = similarity[i].topk(top_ins)
    top_texts = [instructions[idx] for idx in topk.indices.cpu().numpy()]
    results.append({
        "image": os.path.basename(image_paths[i]),
        "true": instructions[i],
        "predicted": top_texts[0],
        "top_3": top_texts
    })

results_df = pd.DataFrame(results)
results_df.to_csv("results.csv", index=False)
print("Results saved to results.csv")