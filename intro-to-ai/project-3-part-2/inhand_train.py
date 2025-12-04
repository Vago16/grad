# inhand_train.py (Student Skeleton)
import os
import numpy as np
import time
from inhand_env import CanRotateEnv 
# --- TODO: Import your agent class ---
from agent import MyRLAgent  # e.g., PPOAgent

# Create a directory to save logs and models
log_dir = "my_agent_logs/"
os.makedirs(log_dir, exist_ok=True)

# --- Configuration ---
TOTAL_TIMESTEPS = 25_000     #changed for quicker learning and without my cpu giving out
STEPS_PER_COLLECT = 1024  # How many steps to run per "collect" phase, changed for quicker learning to help responsiveness 
LEARNING_RATE = 3e-4
DEVICE = 'cpu' # 'cuda' or 'cpu'

# --- TODO: Initialize the Environment ---
env = CanRotateEnv(render_mode="headless")
print(f"Observation space: {env.observation_space.shape}")
print(f"Action space: {env.action_space.shape}")

# --- TODO: Initialize your Agent ---
agent = MyRLAgent(
     obs_space_shape=env.observation_space.shape,
     action_space_shape=env.action_space.shape,
     learning_rate=LEARNING_RATE,
     device=DEVICE
 )
# agent.load_model("my_agent.pth") # Optional: to continue training

print("Starting training...")

# --- TODO: Write the main training loop ---
# This is just one example of an on-policy (like PPO) training loop.
# An off-policy loop (like DDPG/SAC) would look different.

obs, info = env.reset()
global_step = 0

while global_step < TOTAL_TIMESTEPS:
    
    # --- 1. Collect a batch of experiences ---
    obs_buf = []
    act_buf = []
    adv_buf = []
    ret_buf = []
    logp_buf = []
    reward_buf = []  
    value_buf = []   
    
    print(f"Collecting trajectory... (Step {global_step}/{TOTAL_TIMESTEPS})")
    
    for _ in range(STEPS_PER_COLLECT):
        # --- TODO: Get an action from your agent's policy ---
        action, log_prob, value = agent.get_action_and_value(obs)
        #action = env.action_space.sample() # Placeholder: Replace with your agent's action
        
        # --- TODO: Step the environment ---
        next_obs, reward, terminated, truncated, info = env.step(action)
        
        # --- TODO: Store the transition in your buffer ---
        obs_buf.append(obs)
        act_buf.append(action)
        logp_buf.append(log_prob.cpu().numpy())
        value_buf.append(value.cpu().numpy().squeeze())
        reward_buf.append(reward)
        
        global_step += 1
        obs = next_obs
        
        #handle episode end
        if terminated or truncated:
            print(f"Episode finished at step {global_step}.")
            obs, info = env.reset()

    ###compute returns and advantages
    #convert buffer lists to np arrays, data format need for PyTorch
    obs_buf = np.array(obs_buf, dtype=np.float32)
    act_buf = np.array(act_buf, dtype=np.float32)
    reward_buf = np.array(reward_buf, dtype=np.float32)
    value_buf = np.array(value_buf, dtype=np.float32)
    logp_buf = np.array(logp_buf, dtype=np.float32)

    #variables for computing
    gamma = 0.99  #discount factor
    lam = 0.95    #GAE lambda(Generalized Advantage Estimationa)

    #compute advantage
    adv_buf = np.zeros_like(reward_buf)
    lastgaelam = 0
    for t in reversed(range(len(reward_buf))):
        next_value = value_buf[t + 1] if t + 1 < len(reward_buf) else 0
        delta = reward_buf[t] + gamma * next_value - value_buf[t]
        adv_buf[t] = lastgaelam = delta + gamma * lam * lastgaelam

    #compute returns
    ret_buf = adv_buf + value_buf
    ret_buf = ret_buf.astype(np.float32)  #ensure float32

    # --- 2. Update the agent's policy ---
    # (This is where you'd calculate advantages, PPO clip loss, etc.)
    print("Updating policy...")
    # --- TODO: Call your agent's update/learn function ---
    agent.learn(obs_buf, act_buf, adv_buf, ret_buf, logp_buf)

    # --- 3. Save the model periodically ---
    if global_step % 50000 == 0:
        save_path = f"my_agent_logs/model_step_{global_step}.pth"
        # --- TODO: Implement your agent's save method ---
        agent.save_model(save_path)
        print(f"Model saved to {save_path}")


# --- TODO: Final save and cleanup ---
agent.save_model("my_agent_final.pth")
env.close()
print("Training finished.")