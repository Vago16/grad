import torch
import numpy as np
from inhand_env import CanRotateEnv
from inhand_train import DQN, get_macro_actions  

# --- Parameters ---
NUM_ACTIONS = 8
NUM_TEST_EPISODES = 100
STEPS_PER_EPISODE = 200 
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# --- Load environment ---
env = CanRotateEnv(render_mode="headless")  #or 'human' for visuals
obs, info = env.reset()
state_dim = len(obs)

# --- Load trained model ---
policy_net = DQN(state_dim, NUM_ACTIONS)
policy_net.load_state_dict(torch.load("dqn_agent.pth", map_location=device))
policy_net.eval()

macro_actions = get_macro_actions()

#converts quaternarions to yaw
def quat_to_yaw(q):
    # q = [x, y, z, w]
    x, y, z, w = q
    siny_cosp = 2.0 * (w * z + x * y)
    cosy_cosp = 1.0 - 2.0 * (y*y + z*z)
    yaw = np.arctan2(siny_cosp, cosy_cosp)
    return yaw

# --- Testing ---
total_rewards = []
successful_rotations = 0
episode_results = []

for ep in range(NUM_TEST_EPISODES):
    obs, info = env.reset()
    ep_reward = 0
    rotation_done = False

    q = obs[19:23]  #quaternion
    start_yaw = quat_to_yaw(q)
    cumulative_yaw = 0.0
    prev_yaw = start_yaw

    for step in range(STEPS_PER_EPISODE):

        with torch.no_grad():
            obs_tensor = torch.tensor(obs, dtype=torch.float32)
            q_vals = policy_net(obs_tensor)
            action_idx = torch.argmax(q_vals).item()

        action = macro_actions[action_idx]
        action = action + np.random.normal(0, 0.02, size=16)    #randomize agent movement with gaussian noise, to prevent same output for every episode
        obs, reward, terminated, truncated, info = env.step(action)
        ep_reward += reward

        #check if cube rotated 90 degrees
        q = obs[19:23]  #quaternion
        yaw_rad = quat_to_yaw(q)

        #track rotation
        delta_yaw = yaw_rad - prev_yaw
        if delta_yaw > np.pi:
            delta_yaw -= 2*np.pi
        elif delta_yaw < -np.pi:
            delta_yaw += 2*np.pi
        cumulative_yaw += delta_yaw
        prev_yaw = yaw_rad

        rotation_from_start = (np.degrees(cumulative_yaw))  #convert to 0-360 degrees

        if step % 10 == 0:
            print(f"Step {step}: rotation from start = {rotation_from_start:.2f} degrees")

        #check 90 degree rotation
        if not rotation_done and abs(cumulative_yaw) >= np.pi/2:
            rotation_done = True
            successful_rotations += 1
            print(f"*** 90 degree rotation reached at step {step}, rotation from start = {rotation_from_start:.2f} degrees ***")
            break

        if terminated or truncated:
            break

    total_rewards.append(ep_reward)
    episode_results.append(rotation_done)
    status = "SUCCESS" if rotation_done else "FAIL"
    print(f"Episode {ep}: reward={ep_reward:.2f}, {status}")

#save results
with open("dqn_test_results.txt", "w") as f:
    f.write("Episode | Reward | 90deg Rotation\n")
    f.write("--------------------------------\n")
    for ep, (r, success) in enumerate(zip(total_rewards, episode_results)):
        status = "SUCCESS" if success else "FAIL"
        f.write(f"{ep} | {r:.2f} | {status}\n")
    f.write("\n")
    f.write(f"Total successful 90 degree rotations: {successful_rotations} / {NUM_TEST_EPISODES}\n")

print("Testing complete!")
print(f"Total successful 90 degree rotations: {successful_rotations}/{NUM_TEST_EPISODES}")