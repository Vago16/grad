Project 1 Part 2

This project implements an A* search agent that can gather required resources in a grid world and
deliver them to the base while respecting inventory constraints.

Files:
    astar.py- contains the A* search algorithm and helper functions needed for it
    heuristic.py- contains the heuristic necessary for the search algorithm
    main.py- runs the search algorithm on all maps and outputs the path coordinates and total cost associated with each move so far
    maps.py- contains the three hardcoded maps, resources, resource lists, terrains, and terrain costs for movement
    state.py-contains the State class and helper functions, which deal with nodes
    tests.py- some miscellaneous testing of helper functions from some of the files

Requirements:
    Python- only uses general libraries(heapq and itertools)

Run Instructions:
    1. After getting all the files in one directory, navigate to that directory
    2. Run main.py in either GUI or in CLI as 
        $ python3 main.py
    3. The program will output the maps and path and total cost of path as so:
        Map 1:
        B M . G M
        H . S . G
        . S . H H
        G S M S H
        M S G H G

        Path taken and total cost:
        (0, 0), Total cost so far: 0
        ...
    4. You can also run tests.py the same way to see what some helper functions output
        $ python3 tests.py
