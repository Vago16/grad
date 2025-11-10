PROJECT3-Part1

Submitted files:
    inhand_train.py
    inhand_test.py
    hand_movement_test.py- outputs action, location, and orientation at each step of episodes into act_lo_or_step_rl.txt
    act_lo_or_step_rl.txt- Print-out of the action taken at each time step and location and orientation of the objects at each step
    definition.txt- State space, action space, and reward function with justifications
    my_agent_final.pth- Trained RL model

NOTES:
    I was not able to record a video as the functions required to access the GUI are not supported anymore for MacOS.  I instead switched to a fully command line version of the model instead.  I have recorded the steps as detailed in the rubric otherwise.
    I defined an episode as consisting of ten steps, to save on computing cost and speed.  Similarly, I reduced the amount of steps for inhand_train.py, as my CPU cannot handle the amount of steps initialized in the given file.

inhand_test.py sample output:
    Successfully loaded model from my_agent_final.pth
    --- Starting Episode 1 ---
    Episode 1 finished. Total Reward: -85.57
    --- Starting Episode 2 ---
    Episode 2 finished. Total Reward: -106.01
    --- Starting Episode 3 ---
    Episode 3 finished. Total Reward: 28.46
    --- Starting Episode 4 ---
    Episode 4 finished. Total Reward: -74.08
    --- Starting Episode 5 ---
    Episode 5 finished. Total Reward: -0.45
    --- Starting Episode 6 ---
    Episode 6 finished. Total Reward: 64.95
    --- Starting Episode 7 ---
    Episode 7 finished. Total Reward: -410.55
    --- Starting Episode 8 ---
    Episode 8 finished. Total Reward: 114.82
    --- Starting Episode 9 ---
    Episode 9 finished. Total Reward: 5.48
    --- Starting Episode 10 ---
    Episode 10 finished. Total Reward: 574.68