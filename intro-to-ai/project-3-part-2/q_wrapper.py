#q wrapper for q learning to help change the continous state to discrete
#and also simplify output to 4
#only focus on z rotation 
import numpy as np
from inhand_env import CanRotateEnv
from scipy.spatial.transform import Rotation as R
from gymnasium import spaces


class QEnvWrapper:
    def __init__(self, env, num_bins=8, include_height=False, action_scale=1.0):
        self.env = env
        self.num_bins = num_bins
        self.include_height = include_height
        self.action_scale = action_scale 

        self.base_macro_actions = [
            np.array([ 0.05]*16),        #Open all fingers
            np.array([-0.05]*16),        #Close all fingers
            np.array([ 0.04]*8 + [-0.04]*8),  #Wrist twist clockwise
            np.array([-0.04]*8 + [ 0.04]*8),  #Wrist twist counter-clockwise
            np.array([ 0.03]*16),        #Slight lift / extend fingers
            np.array([-0.03]*16),        #Slight lower / relax fingers
            np.array([ 0.02, -0.02]*8)   #Small twist / combined movement
        ]

        #scale macro actions
        self.macro_actions = [a * self.action_scale for a in self.base_macro_actions]
        self.num_actions = len(self.macro_actions)

        #minimal state: Z-rotation ± optionally height
        self.low = 0.0
        self.high = 2 * np.pi  #wrap Z-rotation into [0, 2π] 0-360 degrees
        self.low_height = 0.0
        self.high_height = 1.0  

        if include_height:
            self.num_states = num_bins * num_bins
        else:
            self.num_states = num_bins


        #create bins
        self.z_bins = np.linspace(0, 2*np.pi, self.num_bins + 1)
        if include_height:
            self.h_bins = np.linspace(self.low_height, self.high_height, num_bins)
    
    def get_macro_action(self, action_index):
        return self.macro_actions[action_index]

    def _discretize(self, obs):
        # bs[-1] or obs[cube is at]
        z_rot = (self.get_z_rotation(obs) + np.random.uniform(-1e-3, 1e-3)) % (2*np.pi) #avoid sticking to edge of state/bin
        epsilon = 1e-6
        z_bin = np.digitize(z_rot % (2*np.pi), self.z_bins - epsilon) - 1
        z_bin = int(np.clip(z_bin, 0, self.num_bins - 1)) 

        if self.include_height:
            height = self.get_height(obs)
            h_bin = np.digitize(height, self.h_bins) - 1
            h_bin = min(max(h_bin, 0), self.num_bins - 1)
            return z_bin * self.num_bins + h_bin
        else:
            return z_bin

    def get_z_rotation(self, obs):
        #obs[-4:] = object quaternion [w, x, y, z]
        w, x, y, z = obs[-4:]
        # onvert quaternion to Z rotation
        siny_cosp = 2 * (w * z + x * y)
        cosy_cosp = 1 - 2 * (y*y + z*z)
        yaw = np.arctan2(siny_cosp, cosy_cosp)
        return yaw % (2*np.pi)

    def get_height(self, obs):
        #obs[-7:-4] = position xyz of object
        return obs[-4+2]  #z position

    def reset(self):
        obs, info = self.env.reset()
        return self._discretize(obs)

    def step(self, action):
        #variables needed for q-learning
        real_action = self.macro_actions[action]
        obs, reward, terminated, truncated, info = self.env.step(real_action)
        state = self._discretize(obs)
        return state, reward, terminated, truncated, info
    
    #clone environment
    def close(self):    
        if hasattr(self.env, "close"):
            self.env.close()
