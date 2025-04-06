NAME := whs_sniff

CXX := c++
CXXFLAGS := -Wall -Wextra -Werror -std=c++11 -lpcap -g3 -O0

SOURCES := 	main.cpp \
			whs_sniff.cpp \
			whs_sniff_tcpdump.cpp
OBJECTS := $(SOURCES:.cpp=.o)

all: $(NAME)

$(NAME): $(OBJECTS)
	$(CXX) $(OBJECTS) -o $@ $(CXXFLAGS)

%.o: %.cpp
	$(CXX) -c $< -o $*.o $(CXXFLAGS)

clean:
	rm -rf $(OBJECTS)

fclean: clean
	rm -f $(OBJECTS) $(NAME)

re: fclean all


.PHONY: all clean fclean re