// Microsoft Visual C++ Security Workarounds
#if defined (_MSC_VER)
# define _CRT_SECURE_NO_WARNINGS
#endif

#include "rapidxml-1.13/rapidxml.hpp"

#include <string>
#include <fstream>
#include <sstream>

#include <cstdio>
#include <cstring>

// Microsoft Visual C++ POSIX Warning Workarounds
#if defined(_MSC_VER)
    #define stricmp     _stricmp
    #define strnicmp    _strnicmp
#endif

using namespace rapidxml;

xml_node<>* glv_registry;
xml_node<>* glv_extensions;
xml_node<>* glv_commands;
xml_node<>* glv_features;
xml_node<>* glv_enums;

xml_node<>* find_enum (const char* name)
{
  xml_node<>* enum_group = glv_enums;
  while (enum_group != NULL) {
    xml_node<>* enum_entry = enum_group->first_node ("enum");
    while (enum_entry != NULL) {
      if (! stricmp (enum_entry->first_attribute ("name")->value (), name)) {
        return enum_entry;
      }
      enum_entry = enum_entry->next_sibling ("enum");
    }
    enum_group = enum_group->next_sibling ("enums");
  }

  return NULL;
}

// Finds enum aliases by cross-referencing their value (does not use the alias XML attribute)
xml_node<>* find_next_enum (xml_node<>* enum_node)
{
  xml_node<>* enum_entry = enum_node->next_sibling ("enum");
  while (enum_entry != NULL) {
    if (! stricmp (enum_entry->first_attribute ("value")->value (), enum_node->first_attribute ("value")->value ())) {
      return enum_entry;
    }
    enum_entry = enum_entry->next_sibling ("enum");
  }

  return NULL;
}

xml_node<>* find_action (const char* name, const char* verb) {
  xml_node<>* feature = glv_features;

  while (feature != NULL) {
    xml_node<>* action = feature->first_node (verb);
    while (action != NULL) {
      xml_node<>* entry = action->first_node ();
      while (entry != NULL) {
        if (! stricmp (entry->first_attribute ("name")->value (), name)) {
          return entry->parent ()->parent ();
        }
        entry = entry->next_sibling ();
      }
      action = action->next_sibling (verb);
    }
    feature = feature->next_sibling ("feature");
  }

  return NULL;
}

xml_node<>* find_next_action (const char* name, xml_node<>* feature, const char* verb) {
  feature = feature->next_sibling ("feature");

  while (feature != NULL) {
    xml_node<>* action = feature->first_node (verb);
    while (action != NULL) {
      xml_node<>* entry = action->first_node ();
      while (entry != NULL) {
        if (! stricmp (entry->first_attribute ("name")->value (), name)) {
          return entry->parent ()->parent ();
        }
        entry = entry->next_sibling ();
      }
      action = action->next_sibling (verb);
    }
    feature = feature->next_sibling ("feature");
  }

  return NULL;
}


// TODO: Multiple extensions may fit the bill
xml_node<>* find_ext_req (const char* name) {
  xml_node<>* extension = glv_extensions->first_node ("extension");

  while (extension != NULL) {
    xml_node<>* require = extension->first_node ("require");
    while (require != NULL) {
      xml_node<>* entry = require->first_node ();
      while (entry != NULL) {
        if (! stricmp (entry->first_attribute ("name")->value (), name)) {
          return entry->parent ()->parent ();
        }
        entry = entry->next_sibling ();
      }
      require = require->next_sibling ("require");
    }
    extension = extension->next_sibling ("extension");
  }

  return NULL;
}


// TODO: Add support for reverse command aliasing
xml_node<>* find_command(const char* name)
{
  xml_node<>* command = glv_commands->first_node ("command");

  while (command != NULL) {
    xml_node<>* command_name = command->first_node ("proto")->first_node ("name");
    if (! stricmp (command_name->value (), name))
      return command;
    command = command->next_sibling ("command");
  }

  return NULL;
}

// Finds command aliases using the actual `alias` node in the XML registry
xml_node<>* find_next_command_alias (xml_node<>* command_node, xml_node<>* current)
{
  xml_node<>* command = current->next_sibling ("command");
  while (command != NULL) {
    xml_node<>* alias = command->first_node ("alias");
    if (alias != NULL) {
      if (! stricmp (alias->first_attribute ("name")->value (), command_node->first_node ("proto")->first_node ("name")->value ())) {
        return command;
      }
    }
    command = command->next_sibling ("command");
  }

  return NULL;
}


int main (const int argc, const char** argv)
{
  xml_document<> glv_xml;

  std::ifstream     xml_file ("gl.xml");
  std::stringstream xml_buffer;

  if(xml_file.is_open() == false)
  {
    printf (" @ ERROR: Cannot open 'gl.xml'\n");
    return -2;
  }

  char          name [128] = {0};
  const char    *silent="-silent";
  bool          showInfo = true;

  for(int arg=1; arg<argc; ++arg)
  {
      if(strnicmp(argv[arg], silent, strlen(silent)) == 0)
        showInfo = false;
      else
        strncpy(name, argv[arg], 128);
  }

  xml_buffer << xml_file.rdbuf ();
  xml_file.close ();

  std::string xml_str (xml_buffer.str ());
  glv_xml.parse <0> (&xml_str [0]);

  glv_registry   = glv_xml.first_node ();
  glv_extensions = glv_registry->first_node ("extensions");
  glv_commands   = glv_registry->first_node ("commands");
  glv_features   = glv_registry->first_node ("feature");
  glv_enums      = glv_registry->first_node ("enums");

  if(showInfo)
  {
    xml_node<>* feature = glv_features;
    while (feature != NULL) {
      printf ("Feature: [%5s]   %24s   (%2.1f)\n", feature->first_attribute ("api")->value    (),
                                                   feature->first_attribute ("name")->value   (),
                                             atof (feature->first_attribute ("number")->value ()));
      feature = feature->next_sibling ("feature");
    }
  }

  printf ("\n");

  if(name[0] == 0)
  {
    printf ("Enter OpenGL name to search for: ");
    scanf ("%s", name);
  }

  xml_node<>* command_node = find_command (name);
  xml_node<>* enum_node    = find_enum    (name);

  // First search commands
  if (command_node != NULL) {
    printf ("--------------------------------\n");
    printf (" >> Command:  ");

    xml_node<>* return_type = command_node->first_node ("proto")->first_node ("ptype");
    if (return_type != NULL)
      printf ("%s ", return_type->value ());

    printf ("%s%s (", command_node->first_node ("proto")->value (),
                      command_node->first_node ("proto")->first_node ("name")->value ());

    xml_node<>* param = command_node->first_node ("param");
    if (param != NULL) {
      while (param != NULL) {
        xml_node<>* ptype = param->first_node ("ptype");
        if (ptype != NULL)
          printf ("%s ", ptype->value ());
        printf ("%s%s", param->value (),
                        param->first_node ("name")->value  ());
        param = param->next_sibling ("param");

        if (param != NULL)
          printf (", ");
      }
    } else {
      printf ("void");
    }

    printf (")\n\n");

    xml_node<>* extension = find_ext_req (name);
    if (extension != NULL) {
      printf ("  * Provided by %s (%s)\n\n", extension->first_attribute ("name")->value (), extension->first_attribute ("supported")->value ());
    }

    const char* verbs [] = { "require", "deprecate",     "remove"     };
    const char* desc  [] = { "Core in", "Deprecated in", "Removed in" };

    for (size_t i = 0; i < sizeof (verbs) / sizeof (const char *); i++) {
      xml_node<>* command = find_action (name, verbs [i]);

      while (command != NULL) {
        printf ("  * %-15s %24s    (%5s %2.1f)\n", desc [i],
                                                  command->first_attribute ("name")->value   (),
                                                  command->first_attribute ("api")->value    (),
                                            atof (command->first_attribute ("number")->value ()));
        command = find_next_action (name, command, verbs [i]);
      }
    }

    xml_node<>* command_alias = find_next_command_alias (command_node, glv_commands->first_node ("command"));
    if (command_alias != NULL)
      printf ("\n");

    if (command_alias != NULL) {
      while (command_alias != NULL) {
        printf (" >> Command Alias: %s ", command_alias->first_node ("proto")->first_node ("name")->value ());

        xml_node<>* command_extension = find_ext_req (command_alias->first_node ("proto")->first_node ("name")->value ());
        if (command_extension != NULL)
          printf ("\tProvided by %s (%s)\n\n", command_extension->first_attribute ("name")->value (), command_extension->first_attribute ("supported")->value ());
        command_alias = find_next_command_alias (command_node, command_alias);
      }
      printf ("\n");
    }
  }

  // Then search enums
  else if (enum_node != NULL) {
    printf ("--------------------------------\n");

    const long value = strtol (enum_node->first_attribute ("value")->value   (), NULL, 16);
    printf(" >> Enum:   %s is 0x%04X\n\n", enum_node->first_attribute ("name")->value (), size_t(value));

    // For non-core tokens, find the extension
    xml_node<>* enum_core = find_action (name, "require");
    xml_node<>* enum_extension = find_ext_req (enum_node->first_attribute ("name")->value ());
    if (enum_extension != NULL)
      printf ("  * Provided by %s (%s)\n\n", enum_extension->first_attribute ("name")->value (), enum_extension->first_attribute ("supported")->value ());

    const char* verbs [] = { "require", "deprecate",     "remove"     };
    const char* desc  [] = { "Core in", "Deprecated in", "Removed in" };

    for (size_t i = 0; i < sizeof (verbs) / sizeof (const char *); i++) {
      xml_node<>* node = find_action (name, verbs [i]);

      while (node != NULL) {
        printf ("  * %-15s %24s    (%5s %2.1f)\n", desc [i],
                                                   node->first_attribute ("name")->value   (),
                                                   node->first_attribute ("api")->value    (),
                                             atof (node->first_attribute ("number")->value ()));
        node = find_next_action (name, node, verbs [i]);
      }
    }

    printf ("\n");

    xml_node<>* enum_alias = find_next_enum (enum_node);
    if (enum_alias != NULL) {
      while (enum_alias != NULL) {
        printf (" >> Enum Alias: %s ", enum_alias->first_attribute ("name")->value ());

        xml_node<>* extension = find_ext_req (enum_alias->first_attribute ("name")->value ());
        if (extension != NULL)
          printf ("\tProvided by %s (%s)\n", extension->first_attribute ("name")->value (), extension->first_attribute ("supported")->value ());
        enum_alias = find_next_enum (enum_alias);
      }
      printf ("\n");
    }
  }

  else {
    printf ("--------------------------------\n"
            " @ ERROR: '%s' Not Found In GL Registry!\n",
            name);
    return -1;
  }

  return 0;
}
