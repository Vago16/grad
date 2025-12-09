# q_train_agent.py
import os
import numpy as np
from inhand_env import CanRotateEnv
from q_wrapper import QEnvWrapper

# --- Configuration ---
EPISODES = 1000
MAX_STEPS = 200
ALPHA = 0.15          #learning rate
GAMMA = 0.99         #discount factor
EPSILON = 1.0        #initial exploration rate
EPSILON_DECAY = 0.995
MIN_EPSILON = 0.05
NUM_BINS = 8       #discretization for Z-rotation, 45 degrees each
INCLUDE_HEIGHT = False  #originally thought I needed height of cube

#variables to help stuck state
STUCK_THRESHOLD = 15   #if agent stays in same state this many steps, scale up actions
MAX_SCALE = 3.0        #max multiplier
SCALE_INCREMENT = 0.7  # ow much to increase each time stuck
DECAY_SCALE = 0.99     #decay factor when moving

action_scale = 1.0     #initial scale
prev_state = None
stuck_counter = 0

# Create directory for saving logs
log_dir = "q_training_logs"
os.makedirs(log_dir, exist_ok=True)

# --- Initialize environment ---
#base_env = CanRotateEnv(render_mode="headless")  # no GUI
#env = QEnvWrapper(base_env)
base_env = CanRotateEnv(render_mode="headless")
env = QEnvWrapper(base_env, num_bins=NUM_BINS, include_height=False)    #with only z-rotation



print(f"Num discrete states: {env.num_states}")
print(f"Num discrete actions: {len(env.macro_actions)}")

# --- Initialize Q-table ---
Q = np.zeros((env.num_states, len(env.macro_actions)), dtype=np.float32)

episode_rewards = []

#for increasing computation speed and clogging up with logs
log_every = 25

# --- Training loop ---
for ep in range(EPISODES):
    state = env.reset()
    total_reward = 0
    start_angle = env.get_z_rotation(env.env.sim.data.qpos) #initial rotation
    epsilon = max(MIN_EPSILON, EPSILON * (EPSILON_DECAY ** ep)) #epsilomn decay

    #in case of stuck bin
    prev_state = None
    stuck_counter = 0

    for step in range(MAX_STEPS):
        #epsilon greedy action selection
        if np.random.rand() < epsilon:
            action_index = np.random.randint(len(env.macro_actions))
        else:
            action_index = np.argmax(Q[state])

        #step in environment
        #next_state, reward, terminated, truncated, info = env.step(macro_action)
        next_state, reward, terminated, truncated, info = env.step(action_index)

        #adapt macro-actions if stuck
        if prev_state == next_state:
            stuck_counter += 1
        else:
            stuck_counter = 0
            env.action_scale = max(1.0, env.action_scale * DECAY_SCALE)
            env.macro_actions = [a * env.action_scale for a in env.base_macro_actions]

        if stuck_counter >= STUCK_THRESHOLD:
            env.action_scale = min(MAX_SCALE, env.action_scale + SCALE_INCREMENT)
            env.macro_actions = [a * env.action_scale for a in env.base_macro_actions]
            stuck_counter = 0

        prev_state = next_state

        #incentivize rotation in reward
        # Get current rotation angle
        current_angle = env.get_z_rotation(env.env.sim.data.qpos)
        rotated_angle = abs(current_angle - start_angle)

        #add progress-based reward
        reward += 0.1 * rotated_angle   # small bonus proportional to rotation

        #Give a large bonus if 90 degrees is reached
        if rotated_angle >= np.pi / 2:
            reward += 5.0
            done = True

        #Q-learning update
        #q learning algorithm
        Q[state, action_index] += ALPHA * (reward + GAMMA * np.max(Q[next_state]) - Q[state, action_index])

        state = next_state
        total_reward += reward

        # --- Debug prints to see progress ---
        if step % log_every == 0:
            print(f"Ep {ep} Step {step} | state={state}, action={action_index}, reward={reward:.2f}, next_state={next_state}, done={terminated}")


        if terminated or truncated:
            break

    episode_rewards.append(total_reward)

    # --- Episode summary ---
    print(f"Episode {ep} finished | Total reward: {total_reward:.2f} | Steps: {step+1} | Epsilon: {epsilon:.3f}")

# --- Save Q-table and history ---
np.save(os.path.join(log_dir, "q_table.npy"), Q)
np.savez(os.path.join(log_dir, "train_history.npz"),
         rewards=episode_rewards)

print("Training complete. Q-table saved.")
base_env.close()
