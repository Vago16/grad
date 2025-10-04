import maps
import state
import astar
#run the search algorithm
#will work on OOP more in editing for less repetitive code

###MAP 1###
#create the initial state for map_1
initial_state_1 = state.State(
    pos=(0,0),
    backpack=(),
    finished={"Stone": 0, "Iron": 0, "Crystal": 0},
    resources=maps.resource_list_1
    )

#run astar for map_1
path_1 = astar.astar(initial_state_1, maps.map_1, maps.terrain_costs)

if path_1:
    total_cost = 0  #start tallying total cost
    previous_state = None   #there is no previous state at first
    maps.print_map(maps.map_1, 1)   #print map
    print("Path taken and total cost:")
    for s in path_1:
        coordinate = s.pos
        if previous_state is not None:  #if there is a previous state
            terrain = maps.map_1[coordinate[0]][coordinate[1]]      #takes row and coloumn of coordinate and finds terrain
            movement_cost = maps.terrain_costs[terrain] + 1     #gets movement cost for the specific terrain tile
            total_cost += movement_cost
        
        print(f"{coordinate}, Total cost so far: {total_cost}")
        previous_state = s     #adds in previous state
else:
    print("No path for map_1 found.")

print()
###MAP 2###
#create the initial state for map_2
initial_state_2 = state.State(
    pos=(0,0),
    backpack=(),
    finished={"Stone": 0, "Iron": 0, "Crystal": 0},
    resources=maps.resource_list_2
    )

#run astar for map_1
path_2 = astar.astar(initial_state_2, maps.map_2, maps.terrain_costs)

if path_2:
    total_cost = 0  #start tallying total cost
    previous_state = None   #there is no previous state at first
    maps.print_map(maps.map_2, 2)
    print("Path taken and total cost:")
    for s in path_2:
        coordinate = s.pos
        if previous_state is not None:  #if there is a previous state
            terrain = maps.map_2[coordinate[0]][coordinate[1]]      #takes row and coloumn of coordinate and finds terrain
            movement_cost = maps.terrain_costs[terrain] + 1     #gets movement cost for the specific terrain tile
            total_cost += movement_cost
        
        print(f"{coordinate}, Total cost so far: {total_cost}")
        previous_state = s      #adds in previous state
else:
    print("No path for map_2 found.")

print()
#create the initial state for map_3
initial_state_3 = state.State(
    pos=(0,0),
    backpack=(),
    finished={"Stone": 0, "Iron": 0, "Crystal": 0},
    resources=maps.resource_list_3
    )

#run astar for map_3
path_3 = astar.astar(initial_state_3, maps.map_3, maps.terrain_costs)

if path_3:
    total_cost = 0  #start tallying total cost
    previous_state = None   #there is no previous state at first
    maps.print_map(maps.map_3, 3)
    print("Path taken and total cost:")
    for s in path_3:
        coordinate = s.pos
        if previous_state is not None:  #if there is a previous state
            terrain = maps.map_3[coordinate[0]][coordinate[1]]      #takes row and coloumn of coordinate and finds terrain
            movement_cost = maps.terrain_costs[terrain] + 1     #gets movement cost for the specific terrain tile
            total_cost += movement_cost
        
        print(f"{coordinate}, Total cost so far: {total_cost}")
        previous_state = s      #adds in previous state
else:
    print("No path for map_3 found.")

print()