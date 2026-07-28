from volatility3.framework.objects.utility import array_to_string

# Steps to follow
# 1. Resolve the type of task_struct and the address of init_task
# 2. Construct an object of type task_struct at the address of init_task   


# ------------- Constants -------------
#  It sets a string variable identifying which loaded symbol table to query
symbol_table = "symbol_table_name1"
# Layers provide the read and write interfaces. When you eventually create an object, you must tell Volatility which layer that object "lives" in so it knows how to translate addresses.
memory_layer = "memory_layer"

# Get the fully qualified symbol names for task_struct and init_task
# Note: Volatility 3 uses the exclamation point ! as a separator between the Symbol Table Name and the Symbol/Type Name.
task_struct_symbol = "symbol_table_name1!task_struct"
init_task_symbol = "symbol_table_name1!init_task"
# -------------------------------------

# Resolve type and init_task address
task_struct_type = context.symbol_space.get_type(task_struct_symbol)
init_task_addr = context.symbol_space.get_symbol(init_task_symbol).address

# Construct initial task_struct object
task =context.object(task_struct_type, layer_name=memory_layer, offset=init_task_addr)

# Walk the process/task list
# thats_for_you_to_find_out = "" # TODO
for t in thats_for_you_to_find_out:
    pid = t.pid
    comm = t.comm
    print(f"PID = {pid} \tCOMM = {array_to_string(comm)}")