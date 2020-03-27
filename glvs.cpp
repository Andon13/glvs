// Microsoft Visual C++ Security Workarounds
#if defined(_MSC_VER)
    #define _CRT_SECURE_NO_WARNINGS
#endif

#include "rapidxml-1.13/rapidxml.hpp"

#include <string>
#include <fstream>
#include <sstream>

#include <cstdio>
#include <cstring>
#include <set>
#include <string>
#include <vector>

// Microsoft Visual C++ POSIX Warning Workarounds
#if defined(_MSC_VER)
    #define stricmp     _stricmp
    #define strnicmp    _strnicmp
    #define strlwr      _strlwr
#endif

//-------------------------------------
struct InsensitiveCompare {
    bool operator() (const std::string &a, const std::string &b) const {
        return stricmp(a.c_str(), b.c_str()) < 0;
    }
};

//-------------------------------------
using namespace rapidxml;
using std::vector;
using std::string;
typedef std::set<string, InsensitiveCompare>    string_set;


//-------------------------------------
xml_node<> *glv_registry;
xml_node<> *glv_types;
xml_node<> *glv_groups; // deprecated
xml_node<> *glv_enums;
xml_node<> *glv_commands;
xml_node<> *glv_features;
xml_node<> *glv_extensions;

//-------------------------------------
xml_node<> *
find_enum(const char* name) {
    xml_node<> *enum_group = glv_enums;

    while (enum_group != nullptr) {
        xml_node<> *enum_entry = enum_group->first_node("enum");
        while (enum_entry != nullptr) {
            if (! stricmp(enum_entry->first_attribute("name")->value(), name)) {
                return enum_entry;
            }
            enum_entry = enum_entry->next_sibling("enum");
        }
        enum_group = enum_group->next_sibling("enums");
    }

    return nullptr;
}

// Finds enum aliases by cross-referencing their value(does not use the alias XML attribute)
//-------------------------------------
xml_node<> *
find_next_enum(xml_node<> *enum_node) {
    xml_node<> *enum_entry = enum_node->next_sibling("enum");

    while (enum_entry != nullptr) {
        // Case insensitive since we are really comparing hexadecimal numbers(e.g. 0xF00D vs 0xf00d) and not strings
        if (! stricmp(enum_entry->first_attribute("value")->value(), enum_node->first_attribute("value")->value())) {
            return enum_entry;
        }
        enum_entry = enum_entry->next_sibling("enum");
    }

    return nullptr;
}

//-------------------------------------
xml_node<> *
find_action(const char* name, const char* verb) {
    xml_node<> *feature = glv_features;

    while (feature != nullptr) {
        xml_node<> *action = feature->first_node(verb);
        while (action != nullptr) {
            xml_node<> *entry = action->first_node();
            while (entry != nullptr) {
                if (! stricmp(entry->first_attribute("name")->value(), name)) {
                    return entry->parent()->parent();
                }
                entry = entry->next_sibling();
            }
            action = action->next_sibling(verb);
        }
        feature = feature->next_sibling("feature");
    }

    return nullptr;
}

//-------------------------------------
xml_node<> *
find_next_action(const char* name, xml_node<> *feature, const char* verb) {
    feature = feature->next_sibling("feature");

    while (feature != nullptr) {
        xml_node<> *action = feature->first_node(verb);
        while (action != nullptr) {
            xml_node<> *entry = action->first_node();
            while (entry != nullptr) {
                if (! stricmp(entry->first_attribute("name")->value(), name)) {
                    return entry->parent()->parent();
                }
                entry = entry->next_sibling();
            }
            action = action->next_sibling(verb);
        }
        feature = feature->next_sibling("feature");
    }

    return nullptr;
}


// TODO: Multiple extensions may fit the bill
//-------------------------------------
xml_node<> *
find_ext_req(const char* name) {
    xml_node<> *extension = glv_extensions->first_node("extension");

    while (extension != nullptr) {
        xml_node<> *require = extension->first_node("require");
        while (require != nullptr) {
            xml_node<> *entry = require->first_node();
            while (entry != nullptr) {
                if (! stricmp(entry->first_attribute("name")->value(), name)) {
                    return entry->parent()->parent();
                }
                entry = entry->next_sibling();
            }
            require = require->next_sibling("require");
        }
        extension = extension->next_sibling("extension");
    }

    return nullptr;
}


// TODO: Add support for reverse command aliasing
xml_node<> *find_command(const char* name) {
    xml_node<> *command = glv_commands->first_node("command");

    while (command != nullptr) {
        xml_node<> *command_name = command->first_node("proto")->first_node("name");
        if (! stricmp(command_name->value(), name))
            return command;
        command = command->next_sibling("command");
    }

    return nullptr;
}

// Finds command aliases using the actual `alias` node in the XML registry
//-------------------------------------
xml_node<> *
find_next_command_alias(const char *name, xml_node<> *current) {
    xml_node<> *command = current->next_sibling("command");

    while (command != nullptr) {
        xml_node<> *alias = command->first_node("alias");
        if (alias != nullptr) {
            if (! stricmp(alias->first_attribute("name")->value(), name)) {
                return command;
            }
        }
        command = command->next_sibling("command");
    }

    return nullptr;
}

//-------------------------------------
xml_node<> *
find_next_command_alias(xml_node<> *command_node, xml_node<> *current) {
    return find_next_command_alias(command_node->first_node("proto")->first_node("name")->value(), current);
}

//-------------------------------------
enum eListMode {
    None,
    Types,
    Groups,
    Enums,
    Commands,
    Features,
    Extensions,
};

//---------------------------------
void
set_insert(string_set &set, const string &str, const string &delim) {
    string token;
    size_t prev = 0, pos = 0;

    do {
        pos = str.find(delim, prev);
        if (pos == string::npos)
            pos = str.length();
        token = str.substr(prev, pos - prev);
        if (!token.empty())
            set.insert(token);
        prev = pos + delim.length();
    } while (pos < str.length() && prev < str.length());
}

//---------------------------------
void 
list_types() {
    xml_node<> *node = glv_types;

    while (node != nullptr) {
        xml_node<> *type = node->first_node("type");
        while (type != nullptr) {
            xml_attribute<> *comment = type->first_attribute("comment");
            if (comment != nullptr) {
                printf("// %s\n", comment->value());
            }
            xml_node<> *part = type->first_node();
            while (part != nullptr) {
                char *value = part->value();
                if (value == nullptr || value[0] == 0) {
                    value = part->name();
                }
                if (value != nullptr) {
                    printf("%s", value);
                }
                part = part->next_sibling();
            }
            printf("\n");
            type = type->next_sibling("type");
        }

        node = node->next_sibling("types");
    }
}

//-------------------------------------
void 
find_groups(string_set &groups) {
    xml_node<> *node = glv_enums;

    while (node != nullptr) {
        xml_node<> *enum_entry = node->first_node("enum");
        while (enum_entry != nullptr) {
            xml_attribute<> *attr = enum_entry->first_attribute("group");
            if (attr != nullptr)
                set_insert(groups, attr->value(), ",");

            enum_entry = enum_entry->next_sibling("enum");
        }
        node = node->next_sibling("enums");
    }
}

//-------------------------------------
void 
listGroups() {
    string_set groups;

    find_groups(groups);
    for (const std::string &group : groups) {
        printf("%s\n", group.c_str());
    }
}

//-------------------------------------
void 
listEnums() {
    xml_node<> *enum_group = glv_enums;

    while (enum_group != nullptr) {
        xml_node<> *enum_entry = enum_group->first_node("enum");
        while (enum_entry != nullptr) {
            char *name = enum_entry->first_attribute("name")->value();
            const long value = strtol(enum_entry->first_attribute("value")->value(), nullptr, 16);
            printf("%s = 0x%04x,", name, value);
            xml_attribute<> *attr = enum_entry->first_attribute("group");
            if (attr != nullptr) {
                string_set  groups;
                bool        first = true;
                set_insert(groups, attr->value(), ",");
                printf("\t// ");
                for (const auto &group : groups) {
                    printf("%s%s", first ? "" : ", ", group.c_str());
                    first = false;
                }
            }
            printf("\n");
            enum_entry = enum_entry->next_sibling("enum");
        }
        enum_group = enum_group->next_sibling("enums");
    }
}

//-------------------------------------
void 
listCommands() {
    xml_node<> *command_node = glv_commands->first_node("command");

    while (command_node != nullptr) {
        xml_node<> *return_type = command_node->first_node("proto")->first_node("ptype");
        if (return_type != nullptr)
            printf("%s ", return_type->value());

        printf("%s%s(", command_node->first_node("proto")->value(),
               command_node->first_node("proto")->first_node("name")->value());

        xml_node<> *param = command_node->first_node("param");
        if (param != nullptr) {
            while (param != nullptr) {
                xml_node<> *ptype = param->first_node("ptype");
                if (ptype != nullptr)
                    printf("%s ", ptype->value());
                printf("%s%s", param->value(), param->first_node("name")->value());
                param = param->next_sibling("param");

                if (param != nullptr)
                    printf(", ");
            }
        }
        else {
            printf("void");
        }
        printf(");\n");

        command_node = command_node->next_sibling("command");
    }
}

//-------------------------------------
void 
listFeatures() {
    xml_node<> *feature = glv_features;

    while (feature != nullptr) {
        printf("[%5s] %24s (%2.1f)\n", feature->first_attribute("api")->value(),
               feature->first_attribute("name")->value(),
               atof(feature->first_attribute("number")->value()));

        feature = feature->next_sibling("feature");
    }
}

//-------------------------------------
void 
listExtensions() {
    xml_node<> *extension = glv_extensions->first_node("extension");

    while (extension != nullptr) {
        xml_attribute<> *supported = extension->first_attribute("supported");
        printf("%s [%s]\n", extension->first_attribute("name")->value(), supported != nullptr ? supported->value() : "");
        extension = extension->next_sibling("extension");
    }
}

//-------------------------------------
bool 
readParams(const int argc, const char **argv, eListMode &listMode, char *name) {
    const char *list = "-list";

    for (int arg = 1; arg < argc; ++arg) {
        if (strnicmp(argv[arg], list, strlen(list)) == 0) {
            if (arg + 1 < argc) {
                ++arg;
                if (stricmp(argv[arg], "types") == 0) {
                    listMode = Types;
                }
                else if (stricmp(argv[arg], "groups") == 0) {
                    listMode = Groups;
                }
                else if (stricmp(argv[arg], "enums") == 0) {
                    listMode = Enums;
                }
                else if (stricmp(argv[arg], "commands") == 0) {
                    listMode = Commands;
                }
                else if (stricmp(argv[arg], "features") == 0) {
                    listMode = Features;
                }
                else if (stricmp(argv[arg], "extensions") == 0) {
                    listMode = Extensions;
                }
                else {
                    fprintf(stderr, "Incorrect param '%s'\n", argv[arg]);
                    return false;
                }
            }
            else {
                fprintf(stderr, "Incorrect params\n");
                return false;
            }
        }
        else {
            strncpy(name, argv[arg], 128);
        }
    }

    return true;
}

//-------------------------------------
void
find_aliases(xml_node<> *command_node, string_set &aliases) {
    xml_node<> *command_alias = find_next_command_alias(command_node, glv_commands->first_node("command"));

    while (command_alias != nullptr) {
        aliases.insert(command_alias->first_node("proto")->first_node("name")->value());
        command_alias = find_next_command_alias(command_node, command_alias);
    }
}

//-------------------------------------
void 
print_command_origin(const char *name) {
    static const char *verbs[] = { "require", "deprecate",     "remove" };
    static const char *desc[]  = { "Core in", "Deprecated in", "Removed in" };

    xml_node<> *command_extension = find_ext_req(name);
    if (command_extension != nullptr) {
        printf("  [ Provided by %s (%s)", command_extension->first_attribute("name")->value(),
                                           command_extension->first_attribute("supported")->value());
    }
    else {
        for (size_t i = 0; i < sizeof(verbs) / sizeof(const char *); i++) {
            bool first = true;
            xml_node<> *command = find_action(name, verbs[i]);
            while (command != nullptr) {
                printf("%s%s (%s %2.1f)", first ? "  [ " : ",",
                                          first ? desc[i] : "",
                                          command->first_attribute("api")->value(),
                                          atof(command->first_attribute("number")->value()));

                command = find_next_action(name, command, verbs[0]);
                first = false;
            }
        }
    }
    printf(" ]\n");
}

//-------------------------------------
void
print_enum_origin(const char *name) {
    static const char *verbs[] = { "require", "deprecate",     "remove" };
    static const char *desc[]  = { "Core in", "Deprecated in", "Removed in" };

    bool foundL1 = false;
    bool       foundL2 = false;
    for (size_t i = 0; i < sizeof(verbs) / sizeof(const char *); i++) {
        bool       foundL3 = false;
        xml_node<> *node = find_action(name, verbs[i]);

        while (node != nullptr) {
            printf("%s%s%s %s %2.1f", foundL1 ? "," : "  [",
                   foundL2 ? "" : " ",
                   foundL3 ? "" : desc[i],
                   node->first_attribute("api")->value(),
                   atof(node->first_attribute("number")->value()));

            node = find_next_action(name, node, verbs[i]);
            foundL3 = true;
            foundL2 = true;
            foundL1 = true;
        }
        foundL2 = false;
    }

    xml_node<> *enum_extension = find_ext_req(name);
    if (enum_extension != nullptr)
        printf("%sProvided by %s (%s)", foundL1 ? ", " : "  [ ",
               enum_extension->first_attribute("name")->value(),
               enum_extension->first_attribute("supported")->value());
    printf(" ]\n");
}

//-------------------------------------
int 
main(const int argc, const char** argv) {
    xml_document<> glv_xml;

    char        name[128] = { 0 };
    eListMode   listMode = None;

    if (readParams(argc, argv, listMode, name) == false) {
        return -3;
    }

    std::ifstream     xml_file("gl.xml");
    std::stringstream xml_buffer;

    if (xml_file.is_open() == false) {
        printf(" @ ERROR: Cannot open 'gl.xml'\n");
        return -2;
    }

    xml_buffer << xml_file.rdbuf();
    xml_file.close();

    std::string xml_str(xml_buffer.str());
    glv_xml.parse <0>(&xml_str[0]);

    glv_registry   = glv_xml.first_node();
    glv_types      = glv_registry->first_node("types");
    glv_groups     = glv_registry->first_node("groups");
    glv_extensions = glv_registry->first_node("extensions");
    glv_commands   = glv_registry->first_node("commands");
    glv_features   = glv_registry->first_node("feature");
    glv_enums      = glv_registry->first_node("enums");
    
    //--
    if (listMode != None) {
        switch (listMode) {
            case Types:
                list_types();
                break;

            case Groups:
                listGroups();
                break;

            case Enums:
                listEnums();
                break;

            case Commands:
                listCommands();
                break;

            case Features:
                listFeatures();
                break;

            case Extensions:
                listExtensions();
                break;

            default:
                break;
        }

        return 0;
    }

    if (name[0] == 0) {
        xml_node<> *feature = glv_features;

        while (feature != nullptr) {
            printf("Feature: [%5s] %24s (%2.1f)\n", feature->first_attribute("api")->value(),
                                                    feature->first_attribute("name")->value(),
                                                    atof(feature->first_attribute("number")->value()));
            feature = feature->next_sibling("feature");
        }

        printf("\nEnter OpenGL name to search for: ");
        scanf("%s", name);
        printf("\n");
    }

    xml_node<> *command_node = find_command(name);
    xml_node<> *enum_node    = find_enum(name);

    // First search commands
    if (command_node != nullptr) {
        printf(">> Command:\n   ");

        // Print proto
        xml_node<> *return_type = command_node->first_node("proto")->first_node("ptype");
        if (return_type != nullptr)
            printf("%s ", return_type->value());

        printf("%s%s(", command_node->first_node("proto")->value(),
                        command_node->first_node("proto")->first_node("name")->value());

        xml_node<> *param = command_node->first_node("param");
        if (param != nullptr) {
            while (param != nullptr) {
                xml_node<> *ptype = param->first_node("ptype");
                if (ptype != nullptr)
                    printf("%s ", ptype->value());
                printf("%s%s", param->value(),
                               param->first_node("name")->value());
                param = param->next_sibling("param");

                if (param != nullptr)
                    printf(", ");
            }
        } 
        else {
            //printf("void");
        }
        printf(")");

        print_command_origin(name);
        
        //--
        string_set aliases;

        // Find aliases
        xml_node<> *command_alias = command_node->first_node("alias");
        if (command_alias != nullptr) {
            const char *main_name = command_alias->first_attribute("name")->value();
            aliases.insert(main_name);

            find_aliases(find_command(main_name), aliases);
        }
        else {
            find_aliases(command_node, aliases);
        }
        aliases.erase(name);

        // Print alias info
        for (const string &alias : aliases) {
            printf("   Alias: %s", alias.c_str());

            print_command_origin(alias.c_str());
        }
    }

    // Then search enums
    else if (enum_node != nullptr) {
        const long value = strtol(enum_node->first_attribute("value")->value(), nullptr, 16);
        printf(">> Enum:\n   %s = 0x%04X", enum_node->first_attribute("name")->value(), unsigned(value));

        print_enum_origin(enum_node->first_attribute("name")->value());

        //--
        string_set aliases;
        string_set groups;
        
        // First group
        xml_attribute<> *attr_group = enum_node->first_attribute("group");
        if (attr_group != nullptr) {
            set_insert(groups, attr_group->value(), ",");
        }

        // Find aliases
        while (enum_node->previous_sibling() != nullptr) {
            enum_node = enum_node->previous_sibling();
        }
        while (enum_node != nullptr) {
            xml_attribute<> *attr_name = enum_node->first_attribute("name");
            xml_attribute<> *attr_value = enum_node->first_attribute("value");
            if (attr_name != nullptr && attr_value != nullptr) {
                const long value_aux = strtol(attr_value->value(), nullptr, 16);
                if (value_aux == value) {
                    xml_attribute<> *attr_group = enum_node->first_attribute("group");
                    if (attr_group != nullptr) {
                        set_insert(groups, attr_group->value(), ",");
                    }
                    aliases.insert(attr_name->value());
                }
            }
            enum_node = enum_node->next_sibling();
        }
        aliases.erase(name);

        // Print alias info
        for (const string &alias : aliases) {
            printf("   Alias: %s", alias.c_str());

            print_enum_origin(alias.c_str());
        }

        // Group Info
        if (groups.empty() == false) {
            printf("   Groups: ");
            bool first = true;
            for (const auto &group : groups) {
                printf("%s%s", first ? "" : ", ", group.c_str());
                first = false;
            }
        }
    }

    else {
        string_set groups;

        find_groups(groups);
        if (groups.find(name) != groups.end()) {
            xml_node<> *node = glv_enums;

            while (node != nullptr) {
                xml_node<> *enum_entry = node->first_node("enum");
                while (enum_entry != nullptr) {
                    xml_attribute<> *attr = enum_entry->first_attribute("group");
                    if (attr != nullptr) {
                        if (string(strlwr(attr->value())).find(strlwr(name)) != string::npos) {
                            printf("%s = %s, //", enum_entry->first_attribute("name")->value(), enum_entry->first_attribute("value")->value());
                            print_enum_origin(enum_entry->first_attribute("name")->value());
                        }
                    }
                    enum_entry = enum_entry->next_sibling("enum");
                }
                node = node->next_sibling("enums");
            }
        }
        else{
            printf(" @ ERROR: '%s' Not Found In GL Registry!\n", name);
            return -1;
        }
    }

    return 0;
}
