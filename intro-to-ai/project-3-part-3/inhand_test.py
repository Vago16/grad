# q_test_agent.py
import time
import numpy as np
from inhand_env import CanRotateEnv
from q_wrapper import QEnvWrapper

# --- Configuration ---
Q_TABLE_PATH = "q_training_logs/q_table.npy"
NUM_BINS = 8
NUM_TRIALS = 200
rotation_threshold = np.pi / 2   # 90 degrees
MAX_STEPS = 200
OUTPUT_FILE = "rotation_times.txt"

# --- Load environment ---
base_env = CanRotateEnv(render_mode="headless")
env = QEnvWrapper(base_env, num_bins=NUM_BINS, include_height=False)

# --- Load Q-table ---
try:
    Q = np.load(Q_TABLE_PATH)
    print(f"Successfully loaded Q-table from {Q_TABLE_PATH}")
except Exception as e:
    print(f"Error loading Q-table: {e}")
    exit()

rotation_times = []

# open file to write
with open(OUTPUT_FILE, "w") as f:
    f.write("Trial,Time(s),Steps,Success\n")

    for trial in range(NUM_TRIALS):
        print(f"\nStarting trial {trial+1}...")
        state = env.reset()

        start_angle = env.get_z_rotation(env.env.sim.data.qpos)
        done = False
        step_count = 0
        start_time = time.time()
        success = False

        max_rotated_angle = 0
        while not done and step_count < MAX_STEPS:
            action = np.argmax(Q[state])
            step_result = env.step(action)

            if len(step_result) == 5:
                next_state, reward, terminated, truncated, info = step_result
                done = terminated or truncated
            else:
                next_state, reward, done, info = step_result

            state = next_state

            current_angle = env.get_z_rotation(env.env.sim.data.qpos)
            rotated_angle = abs(current_angle - start_angle)

            #track maximum rotation in episode
            if rotated_angle > max_rotated_angle:
                max_rotated_angle = rotated_angle

            if rotated_angle >= rotation_threshold:
                success = True
                break

            step_count += 1

        end_time = time.time()
        elapsed = end_time - start_time
        rotation_times.append(elapsed)

        #print each trial result
        if success:
            print(f"Trial {trial+1} — Reached 90° in {elapsed:.3f}s (steps: {step_count})")
        else:
            print(f"Trial {trial+1} — FAILED")

        
        f.write(f"{trial+1},{elapsed:.3f},{step_count},{success}\n")

    #write summary to output file
    average_time = sum(rotation_times) / NUM_TRIALS
    f.write(f"\nAverage Time: {average_time:.3f}s\n")
    f.write(f"Fastest Time: {min(rotation_times):.3f}s\n")
    f.write(f"Slowest Time: {max(rotation_times):.3f}s\n")

#print summary to log
print(f"\nAverage time to rotate 90° over {NUM_TRIALS} trials: {average_time:.2f} seconds")
print(f"Fastest time: {min(rotation_times):.2f}s")
print(f"Slowest time: {max(rotation_times):.2f}s")
print(f"Results also written to {OUTPUT_FILE}")
