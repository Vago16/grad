PROJECT 2 PART 2 README
 started at 10% with patch32, then worked on prompt engineering to bring it up to 20%, then changed to patch16 for 25%, and worked more on prompt engineering for 33%

 Files/Folders in directory used for Project-2-Part-2
    /kitchen_5000- contains database of original 5000 images to choose from (https://huggingface.co/datasets/RitaSha/kitchenware_5000)
    utensil_instructions.json- constains 3 instructions each  for 10 classes of   images
    vis_lang_ds.py- script to grab images from relevant classes in      kitchenware_5000 directory and pair them up with instructions in utensil_instructions.json and saves them to paired_ds.csv
    paired_ds.csv- image-instruction pairs to be analyzed by CLIP_model.py
    CLIP_model.py- pretrained CLIP model based off of one from huggingface, outputs accuracy based on input and saves the results to results.csv
    results.csv-qualitative results from the CLIP model

To run the model ideally:
   1. Have all these files/folders in same directory
   2. Run vis_lang_ds.py to create image-instruction pairs
   3. Run CLIP_model.py and check accuracy in terminal
