import os
import random
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from collections import deque
from inhand_env import CanRotateEnv

#hyperparemeters
EPISODES = 550
STEPS_PER_EPISODE = 200
LR = 1e-3
GAMMA = 0.99
EPSILON = 1.0
EPSILON_DECAY = 0.995
MIN_EPSILON = 0.05
MEMORY_SIZE = 50000
BATCH_SIZE = 64
TARGET_UPDATE = 50
NUM_ACTIONS = 8


device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

#deep q learning
class DQN(nn.Module):
    def __init__(self, input_dim, output_dim):
        super().__init__()
        self.model = nn.Sequential(
            nn.Linear(input_dim, 128),
            nn.ReLU(),
            nn.Linear(128, 128),
            nn.ReLU(),
            nn.Linear(128, output_dim)
        )

    def forward(self, x):
        return self.model(x)

#macro actions of joint movements
def get_macro_actions():
    return [
        np.array([ 0.30]*16),                     # 0: open fingers
        np.array([-0.30]*16),                     # 1: close fingers
        np.array([ 0.35]*8 + [-0.35]*8),          # 2: twist CW
        np.array([-0.35]*8 + [ 0.35]*8),          # 3: twist CCW
        np.array([ 0.10]*16),                     # 4: expand
        np.array([-0.10]*16),                     # 5: contract
        np.zeros(16),                             # 6: nothing
        np.array([-0.25, 0.25]*8)               # 7: alternate twist
    ]

# --- Replay memory ---
memory = deque(maxlen=MEMORY_SIZE)

def store_experience(exp):
    memory.append(exp)

def sample_batch():
    batch = random.sample(memory, BATCH_SIZE)
    states, actions, rewards, next_states, dones = zip(*batch)
    return (
        torch.from_numpy(np.array(states, dtype=np.float32)),
        torch.from_numpy(np.array(actions, dtype=np.int64)),
        torch.from_numpy(np.array(rewards, dtype=np.float32)),
        torch.from_numpy(np.array(next_states, dtype=np.float32)),
        torch.from_numpy(np.array(dones, dtype=np.float32))
    )

#training loop
def train():
    env = CanRotateEnv(render_mode="headless")
    obs, info = env.reset()
    state_dim = len(obs)

    policy_net = DQN(state_dim, NUM_ACTIONS).to(device)
    target_net = DQN(state_dim, NUM_ACTIONS).to(device)
    target_net.load_state_dict(policy_net.state_dict())
    target_net.eval()

    optimizer = optim.Adam(policy_net.parameters(), lr=LR)
    macro_actions = get_macro_actions()

    log_file = open("dqn_training_log.txt", "w")

    global EPSILON

    for ep in range(EPISODES):
        obs, info = env.reset()
        total_reward = 0

        for step in range(STEPS_PER_EPISODE):
            if random.random() < EPSILON:
                action_idx = np.random.randint(NUM_ACTIONS)
            else:
                with torch.no_grad():
                    obs_tensor = torch.tensor(obs, dtype=torch.float32, device=device)
                    q_vals = policy_net(obs_tensor)
                    action_idx = torch.argmax(q_vals).item()

            action = macro_actions[action_idx]
            next_obs, reward, terminated, truncated, info = env.step(action)
            done = terminated or truncated

            reward_clipped = np.clip(reward, -1.0, 1.0)
            store_experience((obs, action_idx, reward_clipped, next_obs, done))

            obs = next_obs
            total_reward += reward

            MIN_MEMORY_BEFORE_TRAIN = 1000
            if len(memory) >= MIN_MEMORY_BEFORE_TRAIN:
                states, actions, rewards, next_states, dones = sample_batch()
                states, actions, rewards, next_states, dones = \
                    states.to(device), actions.to(device), rewards.to(device), next_states.to(device), dones.to(device)

                with torch.no_grad():
                    next_q = target_net(next_states).max(dim=1)[0]
                    q_target = rewards + GAMMA * next_q * (1 - dones)

                q_values = policy_net(states)
                q_current = q_values.gather(1, actions.unsqueeze(1)).squeeze()
                loss = nn.MSELoss()(q_current, q_target)

                optimizer.zero_grad()
                loss.backward()
                optimizer.step()

            if done:
                break

        if ep % TARGET_UPDATE == 0:
            target_net.load_state_dict(policy_net.state_dict())

        EPSILON = max(MIN_EPSILON, EPSILON * EPSILON_DECAY)

        print(f"EP {ep}, reward={total_reward:.3f}, eps={EPSILON:.3f}")
        log_file.write(f"{ep} {total_reward}\n")

    log_file.close()
    torch.save(policy_net.state_dict(), "dqn_agent.pth")
    print("Training complete!")

#run when executed directly
if __name__ == "__main__":
    train()
