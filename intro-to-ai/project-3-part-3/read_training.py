import numpy as np
import matplotlib.pyplot as plt

#load the training history
history_file = "q_training_logs/train_history.npz"
data = np.load(history_file, allow_pickle=True)


if 'rewards' in data.files:
    rewards = data['rewards'] 
    print("Rewards shape:", rewards.shape)

    #plot total reward per episode
    if rewards.ndim == 2:  # per-step rewards
        total_rewards = rewards.sum(axis=1)
    else:  #per-episode total rewards
        total_rewards = rewards

    plt.plot(total_rewards)
    plt.xlabel("Episode")
    plt.ylabel("Total Reward")
    plt.title("Training Reward over Episodes")
    plt.show()
