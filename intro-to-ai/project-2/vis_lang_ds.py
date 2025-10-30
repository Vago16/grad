# creates matching image-instruction pairs from base image dataset /kitchenware_5000

import os
import json
import random
import csv

#initialize variables for paths
ds_dir = "kitchenware_5000/kitchen_5000images"  #images
json_file = "utensil_instructions.json" #instructions

#load and read json file
#instructions were originally more "instructional"(ie how to use utensils) but I discovered CLIP works better with image descriptors instead
with open(json_file, "r") as f:
    instructions = json.load(f)

#initialize list for image-instruction pairs
pairs = []

#loop over each utensil in json file 
for utensil, texts in instructions.items():
    utensil_path = os.path.join(ds_dir, utensil)    #path to utensil

    #if folder for utensil is missing
    if not os.path.exists(utensil_path):
        print(f"Missing folder for {utensil}, skipping.")
        continue

    #get all images from folder of utensil
    images = [os.path.join(utensil_path, img)
              for img in os.listdir(utensil_path)
              if img.lower().endswith((".jpg", ".jpeg", ".png"))]
    
    #if issues with getting images/no images in folder for whatever reason
    if not images:
        print(f"No images found for {utensil}, skipping.")
        continue

    #select 3 random images 
    random.shuffle(images)
    selected_images = images[:3]

    #pair each image with an instruction
    for img_path, text in zip(selected_images, texts):
        pairs.append((img_path, text))

#print statement to make sure script works for image-instruction pairs
print(f"Created {len(pairs)} image–instruction pairs.")
print(f"Example pair:\nImage: {pairs[0][0]}\nInstruction: {pairs[0][1]}")

#save to csv file
with open("paired_ds.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["image_path", "instruction"])
    writer.writerows(pairs)

#print statement to make sure script works for csv saving
print("\n💾 Saved pairs to paired_ds.csv")