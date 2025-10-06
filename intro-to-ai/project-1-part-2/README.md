Project 1 Part 2

This project implements a minimax search agent and random moving agent that can both gather required resources in a grid world and deliver them to the base while respecting inventory constraints.

Files:
    minimax.py- contains the minimax search algorithm and helper functions needed for it
    heuristic.py- contains the heuristic necessary for the search algorithm
    main.py- runs the search algorithm on all maps and outputs the path coordinates for minimax agents and random agents
    maps.py- contains the three hardcoded maps, resources, resource lists, terrains, and terrain costs for movement
    state.py-contains the State class and helper functions, which deal with nodes

Requirements:
    Python

Run Instructions:
    1. After getting all the files in one directory, navigate to that directory
    2. Run main.py in either GUI or in CLI as 
        $ python3 main.py
    3. The program will output the maps and path as so:
       Map 1:
        B M . G M
        H . S . G
        . S . H H
        G S M S H
        M S G H B

        Two minimax player game
        --- Turn 1 ---
        Current turn: Player A
        Pos A: (0, 0), Backpack A: ()
        Pos B: (4, 4), Backpack B: ()
        Delivered so far: {'a': {'Stone': 0, 'Iron': 0, 'Crystal': 0}, 'b': {'Stone': 0, 'Iron': 0, 'Crystal': 0}}
        ...

