import os
import shutil
from sklearn.model_selection import train_test_split

#define paths to datasets
dataset_dir = 'kitchenware_5000/kitchen_5000images'
output_dir = 'kitchenware_split_final'
categories = os.listdir(dataset_dir)

#create output directories
for split in ['train', 'val', 'test']:
    for category in categories:
        os.makedirs(os.path.join(output_dir, split, category), exist_ok=True)

#split and move images to relevant directories
for category in categories:
    category_path = os.path.join(dataset_dir, category)
    images = os.listdir(category_path)

    #first split off 20% for test+val
    train_images, temp_images = train_test_split(images, test_size=0.2, random_state=42)
    #then split temp_images evenly for validation and test (10% each)
    val_images, test_images = train_test_split(temp_images, test_size=0.5, random_state=42)

    #copy images to directories
    for img in train_images:
        shutil.copy(os.path.join(category_path, img), os.path.join(output_dir, 'train', category, img))
    for img in val_images:
        shutil.copy(os.path.join(category_path, img), os.path.join(output_dir, 'val', category, img))
    for img in test_images:
        shutil.copy(os.path.join(category_path, img), os.path.join(output_dir, 'test', category, img))
