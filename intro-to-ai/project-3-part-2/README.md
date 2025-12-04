PROJECT3-Part2

Important files:
    Project-3-Part-2-Summary.docx: contains Training history and the changes of rewards during training, any figures that show the training progress, and a report of the average time needed to rotate the cube by 90 degrees for 200 times.

    inhand_train.py: trains q-table and outputs q_train_logs/ which has q_table.npy and train_history_logs.npz

    inhand_test.py: tests according to rubric specifications, outputs to rotation_times.txt

    q_wrapper.py: wrapper that changes continuous states and many joints into discrete environments and specific movements

    read_training.py: reads training log and creates matplot lib of rewards

    q_training_logs/: folder containing q-table and training log model
            |
             -q_table.npy: trained model of q-table
            |
             -train_history.npz: model containing training logs, accessed with read_training.py
    


NOTES:
    I was not able to record a video as the functions required to access the GUI are not supported anymore for MacOS.  I instead switched to a fully command line version of the model instead.  I have recorded the steps as detailed in the rubric otherwise.
    
