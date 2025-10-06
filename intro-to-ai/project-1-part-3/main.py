import maps
import state
import minimax
#run the search algorithm


def run_minimax_game(map_name, given_map, terrain_costs, resource_list, depth=11, max_turn=50):
    #initialize state
    state_obj = state.State(
    pos_a=(0,0),
    pos_b=(4,4),
    backpack_a=(),
    backpack_b=(),
    finished={"a": {"Stone": 0, "Iron": 0, "Crystal": 0},
              "b": {"Stone": 0, "Iron": 0, "Crystal": 0}},
    resources=resource_list,
    turn='a'
    )
    #keep track of number of turns
    turn_count = 0

    while not state.check_goal(state_obj) and turn_count < max_turn:
        #print statements for debugging
        print(f"--- Turn {turn_count + 1} ---")
        print(f"Current turn: Player {state_obj.turn.upper()}")
        print(f"Pos A: {state_obj.pos_a}, Backpack A: {state_obj.backpack_a}")
        print(f"Pos B: {state_obj.pos_b}, Backpack B: {state_obj.backpack_b}")
        print(f"Delivered so far: {state_obj.finished}\n")
        #while the goal hasnt been reached and below max turn count, get the next state
        new_state = minimax.get_move(state_obj,given_map,terrain_costs,depth)
        state_obj = new_state   #go to next state

        turn_count += 1 #increase turn count

    print(f"\nFinished {map_name}. Final Utility: {minimax.utility(state_obj)}")
    print(f"--- Game finished after {turn_count} turns ---")
    print(f"Final positions: A {state_obj.pos_a}, B {state_obj.pos_b}")
    print(f"Final backpacks: A {state_obj.backpack_a}, B {state_obj.backpack_b}")
    print(f"Resources delivered: {state_obj.finished}")
    print(f"Final utility (A - B): {minimax.utility(state_obj)}\n")

def run_rand_game(map_name, given_map, terrain_costs, resource_list, depth=11, max_turn=100):
    '''
    Run game for minimax versus random agent
    '''
    #initialize state
    state_obj = state.State(
    pos_a=(0,0),
    pos_b=(4,4),
    backpack_a=(),
    backpack_b=(),
    finished={"a": {"Stone": 0, "Iron": 0, "Crystal": 0},
              "b": {"Stone": 0, "Iron": 0, "Crystal": 0}},
    resources=resource_list,
    turn='a'
    )
    #keep track of number of turns
    turn_count = 0

    while not state.check_goal(state_obj) and turn_count < max_turn:
        #print statements for debugging
        print(f"--- Turn {turn_count + 1} ---")
        print(f"Current turn: Player {state_obj.turn.upper()}")
        print(f"Pos A: {state_obj.pos_a}, Backpack A: {state_obj.backpack_a}")
        print(f"Pos B: {state_obj.pos_b}, Backpack B: {state_obj.backpack_b}")
        print(f"Delivered so far: {state_obj.finished}\n")

        #now choose move based on agent
        if state_obj.turn == 'a':
            #Player a is minimax
            new_state = minimax.get_move(state_obj, given_map, terrain_costs, depth)
        else:
            #Player b is random
            new_state = minimax.rand_agent(state_obj, given_map, terrain_costs)

        state_obj = new_state   #go to next state
        turn_count += 1 #increase turn count
    
    print(f"\nFinished {map_name}. Final Utility: {minimax.utility(state_obj)}")
    print(f"--- Game finished after {turn_count} turns ---")
    print(f"Final positions: A {state_obj.pos_a}, B {state_obj.pos_b}")
    print(f"Final backpacks: A {state_obj.backpack_a}, B {state_obj.backpack_b}")
    print(f"Resources delivered: {state_obj.finished}")
    print(f"Final utility (A - B): {minimax.utility(state_obj)}\n")

###Run Simulation##

print("Minimax against random agent")
run_rand_game("Map 1",maps.map_1,maps.terrain_costs, maps.resource_list_1)

print()

maps.print_map(maps.map_1, num=1)
print("Two minimax player game")
run_minimax_game("Map 1",maps.map_1,maps.terrain_costs, maps.resource_list_1)
