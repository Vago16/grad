import os
import random
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from collections import deque
from inhand_env import CanRotateEnv

#hyperparemeters 
EPISODES = 500
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

#device
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")


#neural network initialization
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

#macro actions taken from q_wrapper
def get_macro_actions():
    return [
        np.array([ 0.03]*16),                     # 0: Open fingers
        np.array([-0.03]*16),                     # 1: Close fingers
        np.array([ 0.02]*8 + [-0.02]*8),          # 2: Twist CW
        np.array([-0.02]*8 + [ 0.02]*8),          # 3: Twist CCW
        np.array([ 0.01]*16),                     # 4: Slight expand
        np.array([-0.01]*16),                     # 5: Slight contract
        np.zeros(16),                              # 6: Nothing
        np.array([0.015, -0.015]*8)               # 7: Small twist
    ]

#replay memory for network
memory = deque(maxlen=MEMORY_SIZE)

def store_experience(exp):
    memory.append(exp)


def sample_batch():
    batch = random.sample(memory, BATCH_SIZE)
    states, actions, rewards, next_states, dones = zip(*batch)
    #convert lists to single numpy arrays to speed up training
    states_np = np.array(states, dtype=np.float32)
    next_states_np = np.array(next_states, dtype=np.float32)
    actions_np = np.array(actions, dtype=np.int64)
    rewards_np = np.array(rewards, dtype=np.float32)
    dones_np = np.array(dones, dtype=np.float32)

    return (
        torch.from_numpy(states_np),
        torch.from_numpy(actions_np),
        torch.from_numpy(rewards_np),
        torch.from_numpy(next_states_np),
        torch.from_numpy(dones_np)
    )


#deep q learning neural network setup
env = CanRotateEnv(render_mode="headless")
obs, info = env.reset()
state_dim = len(obs)

policy_net = DQN(state_dim, NUM_ACTIONS)
target_net = DQN(state_dim, NUM_ACTIONS)
target_net.load_state_dict(policy_net.state_dict())
target_net.eval()


optimizer = optim.Adam(policy_net.parameters(), lr=LR)
macro_actions = get_macro_actions()

#training loop
log_file = open("dqn_training_log.txt", "w")

#move networks to device for faster computing
policy_net.to(device)
target_net.to(device)

for ep in range(EPISODES):
    obs, info = env.reset()
    total_reward = 0

    for step in range(STEPS_PER_EPISODE):

        #epsilon-greedy action
        if random.random() < EPSILON:
            action_idx = np.random.randint(NUM_ACTIONS)
        else:
            with torch.no_grad():
                obs_tensor = torch.tensor(obs, dtype=torch.float32, device=device)
                q_vals = policy_net(obs_tensor)
                action_idx = torch.argmax(q_vals).item()

        action = macro_actions[action_idx]

        #step environment
        next_obs, reward, terminated, truncated, info = env.step(action)
        done = terminated or truncated

        #clip reward for stability
        reward_clipped = np.clip(reward, -1.0, 1.0)

        #store experience
        store_experience((obs, action_idx, reward_clipped, next_obs, done))

        obs = next_obs
        total_reward += reward

        #train from memory, minimum memory helps reduce early noise
        MIN_MEMORY_BEFORE_TRAIN = 1000
        if len(memory) >= MIN_MEMORY_BEFORE_TRAIN:
            states, actions, rewards, next_states, dones = sample_batch()

            #move tensors to device for faster computing
            states = states.to(device)
            actions = actions.to(device)
            rewards = rewards.to(device)
            next_states = next_states.to(device)
            dones = dones.to(device)

            #compute Q_target
            with torch.no_grad():
                next_q = target_net(next_states).max(dim=1)[0]
                q_target = rewards + GAMMA * next_q * (1 - dones)

            #compute Q_current
            q_values = policy_net(states)
            q_current = q_values.gather(1, actions.unsqueeze(1)).squeeze()

            #loss function
            loss = nn.MSELoss()(q_current, q_target)

            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

        #end episode
        if done:
            break

    # pdate target network periodically
    if ep % TARGET_UPDATE == 0:
        target_net.load_state_dict(policy_net.state_dict())

    #epsilon decay, exponential
    EPSILON = max(MIN_EPSILON, EPSILON * EPSILON_DECAY)

    print(f"EP {ep}, reward={total_reward:.3f}, eps={EPSILON:.3f}")
    log_file.write(f"{ep} {total_reward}\n")

log_file.close()
torch.save(policy_net.state_dict(), "dqn_agent.pth")
print("Training complete!")
