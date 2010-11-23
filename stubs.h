struct symbol_table {
	char *name;
	void *func;
};

extern struct symbol_table symtable[];
