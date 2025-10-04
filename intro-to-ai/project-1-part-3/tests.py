#testing functions from different files

import maps
import state

####for maps.py####
maps.print_map(maps.map_1, 1)
maps.print_resource_list(maps.resource_list_1, 1)
maps.print_map(maps.map_2, 2)
maps.print_resource_list(maps.resource_list_2, 2)
maps.print_map(maps.map_3, 3)
maps.print_resource_list(maps.resource_list_3, 3)

####for state.py####

#testing to see if state class and functions work
state1 = state.State(
    pos=(0, 0),
    backpack=(),
    finished={"Stone": 0, "Iron": 0, "Crystal": 0},
    resources=maps.resource_list_3
)

state2 = state.State(
    pos=(0, 0),
    backpack=(),
    finished={"Stone": 0, "Iron": 0, "Crystal": 0},
    resources=maps.resource_list_3
)

state3 = state.State(
    pos=(0, 3),
    backpack=(),
    finished={"Stone": 0, "Iron": 1, "Crystal": 0},
    resources=maps.resource_list_3
)

#testing equality
print(state.state1 == state.state2)
print(state.state1 == state.state3)

#testing hash
visited1 = set()
visited1.add(state.state1)
visited1.add(state.state2)
print(len(visited1))

visited2 = set()
visited2.add(state.state1)
visited2.add(state.state3)
print(len(visited2))

#testing print
print(state.state1)
print(state.state2)
print(state.state3)
print() #newline for readability

#Testing get_neighbor function
neighbors = state.get_neighbor(state.state1, maps.map_3, maps.terrain_costs)

for neighbor, cost in neighbors:
    print(f"Move to {neighbor.pos} with cost {cost}")
    print(f"  Backpack: {neighbor.backpack}, Delivered: {neighbor.finished}")
    print()