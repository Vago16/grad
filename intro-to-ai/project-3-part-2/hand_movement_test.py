# q_test_agent_rlstyle.py
import mujoco
import numpy as np
import time
import os
from scipy.spatial.transform import Rotation as R
from q_wrapper import QEnvWrapper
from inhand_env import CanRotateEnv

# --- Helper Functions ---
def get_object_z_rotation(sim, obj_body_id):
    """Calculates the Z-axis rotation of an object from its quaternion."""
    quat_wxyz = sim.data.xquat[obj_body_id]
    quat_xyzw = [quat_wxyz[1], quat_wxyz[2], quat_wxyz[3], quat_wxyz[0]]
    r = R.from_quat(quat_xyzw)
    return r.as_euler('xyz', degrees=True)[2]

def get_object_status_string(sim, obj_body_id):
    """Prepares output string for file logging."""
    pos = sim.data.xpos[obj_body_id]
    quat_wxyz = sim.data.xquat[obj_body_id]
    quat_xyzw = [quat_wxyz[1], quat_wxyz[2], quat_wxyz[3], quat_wxyz[0]]
    r = R.from_quat(quat_xyzw)
    z_rot = r.as_euler('xyz', degrees=True)[2]
    return f"> Object Position (x, y, z): {pos}\n> Object Z Rotation (degrees): {z_rot:.2f}°"

# --- Main Script ---
def main():
    print("Loading environment and Q-table...")

    #1. Initialize environment and wrapper
    base_env = CanRotateEnv(render_mode=None)
    env = QEnvWrapper(base_env)

    #2. Load Q-table
    Q_TABLE_PATH = "q_table.npy"
    try:
        Q = np.load(Q_TABLE_PATH)
        print(f"Successfully loaded Q-table from {Q_TABLE_PATH}")
    except Exception as e:
        print(f"Error loading Q-table: {e}")
        return

    # IDs for MuJoCo object and site
    obj_body_id = env.env.sim.obj_body_id
    site_id = env.env.sim.site_id
    sim = env.env.sim

    # Headless episodes
    EPISODES = 10
    STEPS_PER_EPISODE = 50

    #3. Open file for logging
    with open("q_agent_act_lo_or_step.txt", "w") as f:
        for ep in range(EPISODES):
            f.write(f"\n=== Episode {ep + 1} ===\n")
            state = env.reset()
            
            for step in range(STEPS_PER_EPISODE):
                # Deterministic action from Q-table
                action_id = np.argmax(Q[state])
                next_state, reward, done = env.step(action_id)

                # Step simulation manually for logging object pose
                mujoco.mj_forward(sim.model, sim.data)
                object_status = get_object_status_string(sim, obj_body_id)

                # Log action + object state
                step_info = f"Step {step + 1}: Action ID {action_id}\n{object_status}\n\n"
                f.write(step_info)
                print(step_info, end="")

                state = next_state

                if done:
                    break

                time.sleep(0.05)

if __name__ == "__main__":
    main()
