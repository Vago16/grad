#Reinforcement Learning Agent File
#Uses PPO https://www.geeksforgeeks.org/machine-learning/a-brief-introduction-to-proximal-policy-optimization/
import torch
import torch.nn as nn
import torch.optim as optim
from torch.distributions import Normal
import numpy as np

class MyRLAgent:
    def __init__(self, obs_space_shape, action_space_shape, learning_rate=3e-4, device='cpu', clip_ratio=0.2, value_coef=0.5, entropy_coef=0.01):
        self.device = device
        self.obs_dim = obs_space_shape[0]
        self.act_dim = action_space_shape[0]
        self.clip_ratio = clip_ratio
        self.value_coef = value_coef
        self.entropy_coef = entropy_coef

        # policy network with loss function, the strategy the agent takes to choose actions
        self.policy_net = nn.Sequential(
            nn.Linear(self.obs_dim, 64),
            nn.Tanh(),
            nn.Linear(64, 64),
            nn.Tanh(),
            nn.Linear(64, self.act_dim)
        ).to(self.device)

        #Gaussian value as we are in continuous states
        self.log_std = nn.Parameter(torch.zeros(self.act_dim)).to(self.device)

        #value network, with loss function, expected cumulative reward
        self.value_net = nn.Sequential(
            nn.Linear(self.obs_dim, 64),
            nn.Tanh(),
            nn.Linear(64, 64),
            nn.Tanh(),
            nn.Linear(64, 1)
        ).to(self.device)

        #optimizers, to improve performance
        self.optimizer = optim.Adam(list(self.policy_net.parameters()) + [self.log_std], lr=learning_rate)
        self.value_optimizer = optim.Adam(self.value_net.parameters(), lr=learning_rate)

    # sample action
    def get_action_and_value(self, obs):
        obs_tensor = torch.tensor(obs, dtype=torch.float32, device=self.device)
        mean = self.policy_net(obs_tensor)
        std = torch.exp(self.log_std)
        dist = Normal(mean, std)
        action = dist.sample()
        log_prob = dist.log_prob(action).sum()
        value = self.value_net(obs_tensor)
        return action.detach().cpu().numpy(), log_prob.detach(), value.detach()

    #learn function, with help from ChatGPT https://chatgpt.com/c/690ffca7-77d8-8327-8ffc-82619b1325bf
    def learn(self, obs_buf, act_buf, adv_buf, ret_buf, logp_buf, epochs=10, batch_size=64):

        obs_buf = torch.tensor(obs_buf, dtype=torch.float32, device=self.device)
        act_buf = torch.tensor(act_buf, dtype=torch.float32, device=self.device)
        adv_buf = torch.tensor(adv_buf, dtype=torch.float32, device=self.device)
        ret_buf = torch.tensor(ret_buf, dtype=torch.float32, device=self.device)
        logp_buf = torch.tensor(logp_buf, dtype=torch.float32, device=self.device)

        dataset_size = len(obs_buf)
        for _ in range(epochs):
            for start in range(0, dataset_size, batch_size):
                end = start + batch_size
                batch_obs = obs_buf[start:end]
                batch_act = act_buf[start:end]
                batch_adv = adv_buf[start:end]
                batch_ret = ret_buf[start:end]
                batch_logp_old = logp_buf[start:end]

                # --- Policy Loss ---
                mean = self.policy_net(batch_obs)
                std = torch.exp(self.log_std)
                dist = Normal(mean, std)
                logp = dist.log_prob(batch_act).sum(axis=-1)
                ratio = torch.exp(logp - batch_logp_old)
                clipped_ratio = torch.clamp(ratio, 1 - self.clip_ratio, 1 + self.clip_ratio)
                policy_loss = -torch.mean(torch.min(ratio * batch_adv, clipped_ratio * batch_adv))
                entropy_loss = -torch.mean(dist.entropy())
                
                # --- Value Loss ---
                value = self.value_net(batch_obs).squeeze()
                value_loss = self.value_coef * ((value - batch_ret) ** 2).mean()

                # --- Total Loss ---
                loss = policy_loss + value_loss + self.entropy_coef * entropy_loss

                # --- Gradient Step ---
                self.optimizer.zero_grad()
                self.value_optimizer.zero_grad()
                loss.backward()
                self.optimizer.step()
                self.value_optimizer.step()

    #saving the model
    def save_model(self, path):
        torch.save({
            'policy_state_dict': self.policy_net.state_dict(),
            'value_state_dict': self.value_net.state_dict(),
            'log_std': self.log_std
        }, path)

    #loading the model
    def load_model(self, path):
        checkpoint = torch.load(path, map_location=self.device)
        self.policy_net.load_state_dict(checkpoint['policy_state_dict'])
        self.value_net.load_state_dict(checkpoint['value_state_dict'])
        self.log_std.data = checkpoint['log_std'].data