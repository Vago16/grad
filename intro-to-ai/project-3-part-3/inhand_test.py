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
env = CanRotateEnv(render_mode="human")  # or 'headless' for faster testing
obs, info = env.reset()
state_dim = len(obs)

# --- Load trained model ---
policy_net = DQN(state_dim, NUM_ACTIONS)
policy_net.load_state_dict(torch.load("dqn_agent.pth", map_location=device))
policy_net.eval()

macro_actions = get_macro_actions()

# --- Testing ---
total_rewards = []
successful_rotations = 0
episode_results = []

for ep in range(NUM_TEST_EPISODES):
    obs, info = env.reset()
    ep_reward = 0
    rotation_done = False

    for step in range(STEPS_PER_EPISODE):
        with torch.no_grad():
            obs_tensor = torch.tensor(obs, dtype=torch.float32)
            q_vals = policy_net(obs_tensor)
            action_idx = torch.argmax(q_vals).item()

        action = macro_actions[action_idx]
        obs, reward, terminated, truncated, info = env.step(action)
        ep_reward += reward

        #check if cube rotated 90 degrees
        if not rotation_done and abs(obs[90]) >= np.pi/2:
            rotation_done = True
            successful_rotations += 1

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