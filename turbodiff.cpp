/* 
 * Copyright 2010 Core Security Technologies.
 * 
 * This file is part of turbodiff, an IDA plugin for analyzing differences
 * between binary files.
 * The plugin was designed and developed by Nicolas Economou, from the
 * Exploit Writers team of Core Security Technologies.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * For further details, see the file COPYING distributed with turbodiff.
 */
/****************************************************************************/ 
/****************************************************************************/

/* turbodiff.cpp */

/****************************************************************************/ 
/****************************************************************************/

/* Defines */

#define __NT__
#define COMPILE_IDA_FREE_49

/****************************************************************************/ 
/****************************************************************************/

/* Includes */

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <bytes.hpp>
#include <auto.hpp>
#include <name.hpp>

#include <windows.h>
#include <ctype.h>

#include "list.cpp"
#include "string.cpp"

/****************************************************************************/ 
/****************************************************************************/ 

/* Defines */

#define TD_VERSION        0x101B
#define TD_RELEASE        0x01
#define TD_SUBRELEASE     0x01
#define VERSION           ( TD_VERSION << 16 ) + ( TD_RELEASE << 8 ) + TD_SUBRELEASE

#define NAME_LEN          256
#define MAX_DISASM        4096

#define MAX_INT           0x7fffffff
#define MIN_INT           0x80000000

#define IDENTICAL_MATCH   0
#define CHANGED_1_MATCH   1
#define CHANGED_2_MATCH   2
#define CHANGED_3_MATCH   3
#define UNMATCHED1_MATCH  4
#define UNMATCHED2_MATCH  5

/****************************************************************************/
/****************************************************************************/ 

/* Estructuras */

typedef struct
{
  unsigned int addr_inicial;
  unsigned int addr_final;
  unsigned int longitud;
  unsigned int longitud_en_bytes;
  unsigned int checksum;
  int profundidad;
  unsigned int profundidad2;
  unsigned int peso;
  unsigned int pos_file_disasm;

/* Properties usadas para recorrer el grafo */
  int visitado;
  int id;

/* Properties usadas para diffear funciones */
  int association_id;
  int change_type;

/* Creo una lista PERSISTENTE para guardar las conexiones con otros basic blocks */
  List *basic_blocks_hijos;

/* Creo una lista para guardar las conexiones FUERTES ( llamados a funcion ) */
  unsigned int cantidad_referencias;
  List *funciones_hijas;

/* Creo una lista PERSISTENTE para guardar las conexiones DEBILES ( vtables ) */
  List *ptr_funciones_hijas;

/* Concateno los basic blocks que estan conectados por JUMPs incodicionales */
  List *cadena_basic_blocks;
} Basic_Block;

typedef struct
{
  void *funcion;
  unsigned int direccion_funcion;
  unsigned int referencia;
  unsigned int checksum;
} Basic_Block_Padre;

typedef struct
{
  unsigned int address;
  unsigned int pos;
} Referencia_Vtable;

typedef struct
{
/* Datos generales de la funcion */
  char name [ NAME_LEN ];
  char demangled_name [ NAME_LEN ];
  unsigned int address;
  unsigned int address_equivalente;
  unsigned int longitud;
  unsigned int checksum;
  unsigned int checksum_real;
  unsigned int peso;
  char *graph_ecuation;
  int identica;
  int patcheada;

/* Geometria de la funcion */
  unsigned int conexiones_internas;
  unsigned int cantidad_basic_blocks;
  Basic_Block **basic_blocks;

/* Todas las referencias padres */
  unsigned int cantidad_referencias_padre;
  Basic_Block_Padre *basic_blocks_padres;

/* Todas las referencias padres por vtables */
  List *referencias_padre_x_vtable;

/* Todas las referencias hijas */
  unsigned int cantidad_referencias_hijas;

/* Esto es solo decorativo, los valores se dumpean al file directamente */
  Basic_Block volcado_basic_blocks [ 0 ];
  Basic_Block_Padre volcado_basic_blocks_padres [ 0 ];
  Referencia_Vtable volcado_referencias_x_vtable;
} Funcion;

/****************************************************************************/ 
/****************************************************************************/ 

/* Prototipos */

int comparar_analisis ( void );
int comparar_funciones ( int );

int get_viewers ( List & , List & );
char *get_substring ( char * , char * );
int analizar_programa ( int );
int analizar_funcion ( unsigned int , Funcion * );
int identificar_basic_blocks ( Funcion * , List & , unsigned int , unsigned int , unsigned int );
int compactar_basic_blocks ( Funcion * , List & );
int suprimir_basic_blocks_vacios ( Funcion * , List & );
int search_value_x_dicotomic_style ( List & , unsigned int );
int get_next_instruction ( unsigned int , unsigned int , unsigned int * );
int is_fin_basic_block ( unsigned int , unsigned int );
int is_referencia_interna ( unsigned int , unsigned int , unsigned int * );
int is_referencia_externa_por_codigo ( unsigned int );
int is_referencia_externa_por_dato ( unsigned int );
int is_call ( unsigned int , unsigned int * );
int is_llamado_a_funcion ( unsigned int , unsigned int * );
int is_funcion ( unsigned int );
int is_inicio_basic_block ( Funcion * , List & , unsigned int );
int tienen_un_mismo_padre ( Funcion * , Funcion * );
Basic_Block *get_basic_block ( List & , unsigned int );
Basic_Block *get_basic_block_from_array ( Basic_Block ** , unsigned int , unsigned int );
unsigned int calcular_longitud_funcion ( List & );
void calcular_checksum_funcion ( List & , unsigned int * , unsigned int * );
unsigned int calcular_cantidad_conexiones_internas ( Funcion * );
unsigned int calcular_cantidad_hijos ( Funcion * );
unsigned int get_cantidad_referencias_padre ( Funcion * , unsigned int );
int get_referencias_padre ( Funcion * );
unsigned int get_cantidad_basic_blocks_padres_from_list ( Funcion * , Basic_Block * , List & );
int get_basic_blocks_padres ( Funcion * , Basic_Block * , List & );
int get_basic_blocks_hijos ( Funcion * , Basic_Block * , List & );
Funcion *get_estructura_funcion ( List & , unsigned int );
Funcion *get_estructura_funcion2 ( List & , List & , unsigned int );
void actualizar_checksum_basic_blocks_padres ( List & , List & , Funcion * );
int get_funcion_padre ( unsigned int , unsigned int * );
int is_ptr_a_funcion ( unsigned int , unsigned int * );
int is_ptr_vtable ( unsigned int );
List *get_funciones_de_vtable ( unsigned int );
int get_funciones_undefined ( unsigned int , unsigned int , List & );
int get_referencias_fcode_from ( unsigned int , List & );
int get_referencias_data_from ( unsigned int , List & );
int get_referencias_to ( unsigned int , List & );

///////////////////////

void setear_profundidad_hacia_abajo ( int , Funcion * , Basic_Block * );
void setear_maxima_profundidad_hacia_abajo ( int , Funcion * , Basic_Block * );
void setear_profundidad_hacia_arriba ( int , Funcion * , Basic_Block * );
unsigned int setear_peso_a_basic_blocks ( unsigned int , Funcion * , Basic_Block * );
void poner_ids_a_basic_blocks ( int , Funcion * , Basic_Block * );
char *generar_ecuacion_de_grafo_de_funcion ( Funcion * );
Basic_Block *get_basic_block_by_id ( Funcion * , int );
Basic_Block *get_basic_block_by_association_id ( Funcion * , int );
void liberar_basic_blocks ( Funcion * );

///////////////////////

int guardar_analisis ( char * );
int guardar_desensamblado ( char * );
int guardar_desensamblado_de_funcion ( FILE * , Funcion * );
char *get_instruction ( unsigned int , char * , unsigned int );

///////////////////////

int comparar_files ( char * , char * , char * , int );
void get_formated_name ( Funcion * , char * , unsigned int , int );
int levantar_funciones ( FILE * , List & , List & );
int asociar_funciones ( int , Funcion * , Funcion * , List & , List & , List & , List & );
int tienen_el_mismo_nombre ( Funcion * , Funcion * );
int reconocer_funciones_con_misma_geometria ( List & , List & , List & , List & );
unsigned int reconocer_funciones_x_vtables ( List & , List & , List & , List & , List & , List & );
int son_funciones_equivalentes_x_vtables ( List & , List & , Funcion * , Funcion * );
int son_funciones_iguales ( Funcion * , Funcion * );
int son_funciones_cuasi_identicas ( Funcion * , Funcion * );
int es_funcion_patcheada ( Funcion * , List & , Funcion ** );
int get_funcion_equivalente_x_grafo ( int , Funcion * , Funcion * , Basic_Block * , List & , Funcion * , Funcion ** , Basic_Block * );
int is_condicion_invertida ( Funcion * , Funcion * , Basic_Block * , Basic_Block * );
int is_camino_confiable ( unsigned int , unsigned int , Funcion * , Funcion * , Basic_Block * , Basic_Block * );
int get_funcion_equivalente_x_hijos ( Funcion * , List & , List & , Funcion ** );
int get_funcion_equivalente_x_hijos_x_padres_en_comun ( Funcion * , List & , List & , Funcion ** );
int get_funcion_equivalente_x_hijos_x_unico_padre ( Funcion * , List & , List & , Funcion ** );
int clasificar_funciones_cambiadas ( List & , List & , List & , List & );

///////////////////////

/* Funciones asociadas con el muestreo de los resultados */

int armar_resultados ( void );
int guardar_resultados ( char * , char * );
int levantar_resultados ( char * , char * );
int mostrar_resultados ( char * , char * );
unsigned int mostrar_funciones ( unsigned int );

///////////////////////

int diffear_funciones ( int , char * , char * );
int diffear_y_mostrar_funciones ( char * , char * , Funcion * , Funcion * );
int diffear_funcion_por_grafo ( Funcion * , Funcion * );
int diffear_funcion_recorriendo_grafo ( Funcion * , Funcion * , Basic_Block * , Basic_Block * , unsigned int * );
int diffear_funcion_usando_ids ( Funcion * , Funcion * , unsigned int * );
int diffear_funcion_por_mejor_probabilidad ( Funcion * , Funcion * , unsigned int * );
unsigned int get_porcentaje_equivalencia ( unsigned int , unsigned int , Funcion * , Funcion * , Basic_Block * , Basic_Block * );
int recorrer_camino_de_equivalencia ( unsigned int , unsigned int , Funcion * , Funcion * , Basic_Block * , Basic_Block * , unsigned int * , unsigned int * , unsigned int * );
int is_reverted_condition ( Funcion * , Funcion * , Basic_Block * , Basic_Block * );
unsigned int get_change_type ( Basic_Block * , Basic_Block * );
int armar_grafo_salida ( char * , char * , char * , Funcion * );
void mostrar_grafo ( char * );
void mostrar_grafos ( char * , char * );
void get_ida_path ( unsigned int , char * );

///////////////////////

int buscar_funciones_equivalentes ( char * , char * );

/****************************************************************************/
/****************************************************************************/ 

/* Variables globales */

static char *comment = "turbodiff v1.01b r1.1";
static char *help = "...";
static char wanted_name[] = "turbodiff v1.01b r1.1";
static char wanted_hotkey[] = "Ctrl-F11";

// Version de la aplicacion
unsigned int turbodiff_version = VERSION;

// Puntero a la funcion que interfacea desde IDA con los usuarios
void *ptr_callui;

/* Ubicacion del IDB abierto */
char *idb_path;

// Lista donde voy a guardar la info de todas las funciones del programa
List indice_funciones;
List funciones;

List indice_funciones1;
List funciones1;

List indice_funciones2;
List funciones2;

// Listas donde guardo el resultado del analisis
List funciones1_reconocidas;
List funciones2_reconocidas;
List funciones1_matcheadas;
List funciones2_matcheadas;
List funciones1_geometricamente_identicas;
List funciones2_geometricamente_identicas;
List funciones1_cambiadas;
List funciones2_cambiadas;
List funciones1_irreconocidas;
List funciones2_irreconocidas;
List funciones1_levantadas;
List funciones2_levantadas;
List funciones1_intermedias;
List funciones1_intermedias2;

// Lista donde guardo las direcciones de file1 equivalentes a las funciones de file2
List address_equivalentes;

// Lista donde guardo las direcciones iniciales y finales de los basic blocks
List basic_blocks;

// Lista donde guardo los basic blocks que se unen con otros
List basic_blocks_compuestos [ 2 ];

// Lista donde guardo todas las referencias padre de codigo NO asociado a una funcion
List referencias_undefined;

// Lista donde guardo todas las funciones UNDEFINEDs
List undefined_functions;

// Listas donde guardo el CALL GRAPH de los programas
List *call_graph1;
List *call_graph2;

// Listas donde guardo, en orden, todos los matcheos
List matcheo_1_2;
List resultado1;
List resultado2;

// Archivo donde guarde los resultados
char result_file [ QMAXPATH ];

// Indica que visualizador usar
int visualizador = 0;

// Listas donde guardo el ID del visualizador + el path
List viewer_names;
List viewer_paths;

/****************************************************************************/
/****************************************************************************/ 

int my_msg ( const char *format , ... )
{
  bool ( *my_callui ) ( int , const char * , ... );
  int nbytes;
  va_list va;

/* Resuelvo el simbolo */
  ( unsigned int ) my_callui = * ( unsigned int * ) ptr_callui;

/* Inicializo la lista para parsear los parametros */
  va_start ( va , format );

/* Imprimo el mensaje */
  nbytes = my_callui ( ui_msg , format , va );

/* Reseteo la lista */
  va_end(va);

  return ( nbytes );
}

/****************************************************************************/ 

int my_askaddr ( ea_t *addr , const char *format , ... )
{
  bool ( *my_callui ) ( int , ea_t * , const char * , ... );
  va_list va;
  int ret;

/* Resuelvo el simbolo */
  ( unsigned int ) my_callui = * ( unsigned int * ) ptr_callui;

/* Inicializo la lista para parsear los parametros */
  va_start ( va , format );

/* Imprimo el mensaje */
  ret = my_callui ( ui_askaddr , addr , format , va );

/* Reseteo la lista */
  va_end(va);

  return ( ret );
}

/****************************************************************************/ 

int my_AskUsingForm ( const char *format , ... )
{
  bool ( *my_callui ) ( int , const char * , ... );
  va_list va;
  int code;

/* Resuelvo el simbolo */
  ( unsigned int ) my_callui = * ( unsigned int * ) ptr_callui;

/* Inicializo la lista */
  va_start ( va , format );

/* Muestro al usuario las opciones */
  code = my_callui ( ui_form , format , va );

/* Reseteo la lista */
  va_end(va);

  return code;
}

/****************************************************************************/ 

//  ui_askaddr,           // * Ask an address
                        // Parameters:
                        //      ea_t *answer
                        //      const char *format
                        //      va_list va
                        // Returns: bool success

//  ui_askfile,           // * Ask the user a file name
                        // Parameters:
                        //      int savefile
                        //      const char *default_answer
                        //      const char *format
                        //      va_list va
                        // Returns: file name

/****************************************************************************/ 

char *my_askfile ( int savefile , const char *default_answer , const char *format , ... )
{
  char *( *my_callui ) ( int , int , const char * , const char * , ... );
  va_list va;
  char *file;

/* Resuelvo el simbolo */
  ( unsigned int ) my_callui = * ( unsigned int * ) ptr_callui;

/* Inicializo la lista para parsear los parametros */
  va_start ( va , format );

/* Imprimo el mensaje */
  file = my_callui ( ui_askfile , savefile , default_answer , format , va );

/* Reseteo la lista */
  va_end(va);

  return ( file );
}

/****************************************************************************/ 

void my_close_chooser ( char *title )
{
  char *( *my_callui ) ( int , char * );

/* Resuelvo el simbolo */
  ( unsigned int ) my_callui = * ( unsigned int * ) ptr_callui;

/* Imprimo el mensaje */
  my_callui ( ui_close_chooser , title );
}

/****************************************************************************/ 

unsigned int my_choose ( bool flags , int x1 , int y1 , int x2 , int y2 , void *obj , unsigned int columnas , int *ancho , void *size_function , void *description_function , void *enter_function , void *destroy_function , unsigned int pos )
{
  int ( *my_callui ) ( int , int , int , ... );
  unsigned int ret;

/* Resuelvo el simbolo */
  ( unsigned int ) my_callui = * ( unsigned int * ) ptr_callui;

/* Imprimo el mensaje */
  ret = my_callui (  ui_choose,
                      chtype_generic2,
                      flags,
                      x1, y1, x2, y2,
                      obj,
                      columnas,
                      ancho,
                      size_function,
                      description_function,
                      "Turbodiff results",
                      -1,
                      pos,
                      NULL,
                      NULL,
                      NULL,
                      NULL,
                      enter_function,
                      destroy_function,
                      NULL,
                      NULL
                   );

  return ( ret );
}

/****************************************************************************/

void get_actual_idb_name ( char *idb_name )
{
/* Copio el nombre del IDB */
  qstrncpy ( idb_name , idb_path , strlen ( idb_path ) );
}

/****************************************************************************/ 

void change_extension ( char *filename , char *extension )
{
  char *punto;

/* Busco el punto */
  punto = strrchr ( filename , '.' );

/* Reemplazo las extenciones ".idb" por la nueva extension */
  qstrncpy ( punto + 1 , extension , QMAXPATH - strlen ( filename ) );
}

/****************************************************************************/ 

char *version = " v1.01b r1.1";

static const char pantalla_inicial [] =
"Choose operation\n"
"turbodiff v1.01b r1.1\n"
"Created by Nicolas A. Economou ( neconomou@corest.com )\n"
"Buenos Aires, Argentina ( 2010 )\n"
"\n"
"options\n"
"<take info from this idb:R>"
"<compare with ...:R>"
"<load results from ...:R>"
"<free comparison with ...:R>>"
//"<search equivalent functions (experimental):R>>"
"\n\n\n\n\n\n";

static const char files_a_analizar [] =
"Take the analysis\n"
"turbodiff v1.01b r1.1\n"
"Created by Nicolas A. Economou ( neconomou@corest.com )\n"
"Buenos Aires, Argentina ( 2010 )\n"
"\n\n"
"Important: The analysis will be saved on the current idb path.\n"
"\n\n"
"<analize undefined functions:C>>"
"\n\n";

static const char files_a_comparar [] =
"Select options to compare\n"
"turbodiff v1.01b r1.1\n"
"Created by Nicolas A. Economou ( neconomou@corest.com )\n"
"Buenos Aires, Argentina ( 2010 )\n"
"\n"
//"<patterns\t:A:32:16::>"
"\n"
"<log file\t:A:256:16::>"
"\n"
"\t<use symbols:C>>"
"\n\n"
"\n\n";

static const char funciones_a_comparar [] =
"Write function addresses to compare\n"
"turbodiff v1.01b r1.1\n"
"Created by Nicolas A. Economou ( neconomou@corest.com )\n"
"Buenos Aires, Argentina ( 2010 )\n"
"\n\n"
"<function1\t:$:500:16:::>\n"
"\n"
"<function2\t:$:500:16:::>\n"
"\n\n";

static const char funciones_a_buscar [] =
"turbodiff v1.01b r1.1\n"
"Write only one address functions to search\n"
"\n"
"<function1\t:$:500:16:::>\n"
"\n"
"<function2\t:$:500:16:::>\n"
"\n";

/****************************************************************************/
/****************************************************************************/ 

int __stdcall init ( void )
{
  return PLUGIN_OK;
}

/****************************************************************************/ 

void __stdcall run ( int arg )
{
  String *menu;
  String *viewer;
  String *vname;
  char current_path [ QMAXPATH ];
  char fviewer [ QMAXPATH ];
  char file1 [ QMAXPATH ];
  char file2 [ QMAXPATH ];
  char *file;
  unsigned int initial_time;
  unsigned int final_time;
  unsigned int cont;
  int tipo_operacion = 0;
  int analizar_undefined_functions = FALSE;
  int ret;

  #ifndef COMPILE_IDA_FREE_49
  /* Resuelvo el puntero a la funcion "callui" */
    ptr_callui = GetProcAddress ( GetModuleHandle ( "ida.wll" ) , "callui" );

  /* Averiguo el PATH del IDB actual */
    idb_path = ( char * ) GetProcAddress ( GetModuleHandle ( "ida.wll" ) , "database_idb" );
  #else
  /* Resuelvo el puntero a la funcion "callui" */
    ptr_callui = ( void * ) ( ( unsigned int ) GetModuleHandle ( "ida.wll" ) + 0xd2364 );

  /* Averiguo el PATH del IDB actual */
    idb_path = ( char * ) ( ( unsigned int ) GetModuleHandle ( "ida.wll" ) + 0xf9698 );
  #endif

/////////////////////////

/* Obtengo la lista de viewers disponibles */
  get_viewers ( viewer_names , viewer_paths );

/* String donde van a ir a parar la lista de visualizadores disponibles */
  viewer = new ( String );

/* Si hay algun visualizador */
  if ( viewer_names.Len () > 0 )
  {
  /* Visualizadores disponibles */
    viewer -> Append ( "viewer\n" );

  /* Recorro todos los viewers levantados del archivo de configuracion */
    for ( cont = 0 ; cont < viewer_names.Len () ; cont ++ )
    {
    /* Obtengo el siguiente ID */
      vname = ( String * ) viewer_names.Get ( cont );

    /* Fabrico el TAG para el viewer */
      qsnprintf ( fviewer , QMAXPATH , "<%s:R>" , vname -> Get () );

    /* Agrego el siguiente viewer */
      viewer -> Append ( fviewer );
    }

  /* Cierro la lista de viewers */
    viewer -> Append ( ">" );

  /* Agrego un ENTER por cada n lineas */
    for ( cont = 0 ; cont < viewer_names.Len () ; cont ++ )
    {
    /* Por cada 4 lineas agrego un ENTER demas */
      if ( cont % 4 == 0 )
      {
      /* Agrego dos ENTER */
        viewer -> Append ( "\n\n" );
      }
      else
      {
      /* Agrego un ENTER */
        viewer -> Append ( "\n" );
      }
    }
  }

/* Fabrico las opciones */
  menu = new ( String );
  menu -> Set ( pantalla_inicial );
  menu -> Append ( ( char * ) viewer -> Get () );

/* Menu inicio */
  ret = my_AskUsingForm ( menu -> Get () , &tipo_operacion , &visualizador );

/* Si el usuario apreto ESC */
  if ( ret != 1 )
  {
  /* Salgo */
    return;
  }

//////////////////////////

//  do_unknown ( 0x40a9c0 , 0 );
//  do_data_ex ( 0x40a9c0 , 0x20000400 , 4 , -1 );
//  return;

//////////////////////////

/* Si el usuario quiere analizar files */
  if ( tipo_operacion == 0 )
  {
  /* Pido al usuario la funcion a analizar */
    ret = my_AskUsingForm ( files_a_analizar , &analizar_undefined_functions );

  /* Si el usuario apreto ESC */
    if ( ret != 1 )
    {
    /* Salgo */
      return;
    }
  }
/* Si el usuario quiere diffear funciones */
  else if ( tipo_operacion == 2 )
  {
  /* Comparo las funciones */
    comparar_funciones ( TRUE );

  /* Salgo porque el usuario apreto ESCAPE */
    return;
  }
/* Si el usuario quiere comparar cualquier funcion contra cualquier funcion */
  else if ( tipo_operacion == 3 )
  {
  /* Comparo las funciones */
    comparar_funciones ( FALSE );

  /* Salgo porque el usuario apreto ESCAPE */
    return;
  }

/* Tomo el tiempo actual */
  initial_time = GetTickCount ();

/* Mensaje para el usuario */
  my_msg ( "\nworking ...\n" );

/* Si tengo que sacar un analisis */
  if ( tipo_operacion == 0 )
  {
  /* Levanto todas las funciones del programa */
    analizar_programa ( analizar_undefined_functions );

  /* Obtengo el nombre del IDB actual */
    get_actual_idb_name ( file1 );

  /* Cambio la extension para guardar el desensamblado */
    change_extension ( file1 , "dis" );

  /* Mensaje al usuario */
    my_msg ( "generating %s\n" , file1 );

  /* Guardo el desensamblado */
    guardar_desensamblado ( file1 );

  /* Cambio la extension para guardar el desensamblado */
    change_extension ( file1 , "ana" );

  /* Mensaje al usuario */
    my_msg ( "generating %s\n" , file1 );

  /* Guardo el analisis */
    guardar_analisis ( file1 );
  }
  else
  {
  /* Comparo los analisis tomados previamente */
    comparar_analisis ();

  /* Salgo */
    return;
  }

/* Tomo el tiempo final */
  final_time = GetTickCount ();

/* Mensaje al usuario */
  my_msg ( "elapsed time: %u.%u sec.\n" , ( final_time - initial_time ) / 1000 , ( final_time - initial_time ) % 1000 );

  my_msg ( "done\n" );
}

/****************************************************************************/ 

int get_viewers ( List &viewer_names , List &viewer_paths )
{
  FILE *fviewers;
  String *viewer;
  String *path;
  char ida_path [ MAX_PATH ];
  char buffer [ MAX_PATH ];
  char *end_token;
  char *token;
  char *vname;
  char *vpath;
  int ret = TRUE;

/* Obtengo la ruta de IDA */
  get_ida_path ( QMAXPATH , ida_path );

/* Apunto al file de configuracion en la carpeta de plugins */
  qstrncat ( ida_path , "\\plugins\\turbodiff.cfg" , QMAXPATH );

/* Abro el archivo de configuracion de viewers */
  fviewers = qfopen ( ida_path , "rt" );

/* Si pude abrir el archivo */
  if ( fviewers != NULL )
  {
  /* Levanto la siguiente linea */
    while ( qfgets ( buffer , MAX_PATH , fviewers ) != 0 )
    {
    /* Si es un comentario */
      if ( buffer [ 0 ] == '#' )
      {
      /* Paso a la siguiente linea */
        continue;
      }

    /* Apunto al inicio del buffer */
      token = get_substring ( buffer , "::" );

    /* Si pude obtener un token y es una declaracion del tipo "viewer" */
      if ( ( token != NULL ) && ( strcmp ( token , "viewer" ) == 0 ) )
      {
      /* Obtengo el nombre del viewer */
        token = get_substring ( NULL , "::" );
        vname = token; 

      /* Si pude obtener el nombre del viewer */
        if ( token != NULL )
        {
        /* Obtengo el path del viewer */
          token = get_substring ( NULL , "\r\n" );
          vpath = token;

        /* Si pude obtener el path */
          if ( token != NULL )
          {
          /* Creo los strings para guardar el nombre y el path del viewer */
            viewer = new ( String );
            path = new ( String );

          /* Seteo el nombre del viewer */
            viewer -> Set ( vname );

          /* Seteo el nombre del viewer */  
            path -> Set ( vpath );

          /* Agrego el viewer a la lista */
            viewer_names.Add ( viewer );
            viewer_paths.Add ( path );
          }
        }
      }
    }
  }
/* Si NO pude abrir el archivo */
  else
  {
  /* El archivo de configuracion NO existe */
    ret = FALSE;
  }

/* Cierro el archivo de configuracion */
  qfclose ( fviewers );

  return ( ret );
}

/****************************************************************************/ 

char *get_substring ( char *string , char *separator )
{
  static char *ostring = NULL;
  char *end_string = NULL;
  char *substring;

/* Si tengo que procesar un string NUEVO */
  if ( string != NULL )
  {
  /* Obtengo el inicio del string */
    ostring = string;
  }

/* String a retornar */
  substring = ostring;

/* Si esta abierta la busqueda */
  if ( ostring != NULL )
  {
  /* Busco el separador en el string */
    end_string = strstr ( ostring , separator );
  }

/* Si obtuve un substring */
  if ( end_string != NULL )
  {
  /* Cierro el string donde empieza el separador */
    *end_string = '\x00';

  /* Me posiciono despues del separador */
    ostring = end_string + strlen ( separator );
  }
/* Si NO obtuve un substring */
  else
  {
  /* Cierro la busqueda */
    ostring = NULL;
  }

  return ( substring );
}

/****************************************************************************/ 

int comparar_analisis ( void )
{
  char current_path [ QMAXPATH ];
  char log_file [ QMAXPATH ];
  char file1 [ QMAXPATH ];
  char file2 [ QMAXPATH ];
  char *file;
  unsigned int initial_time;
  unsigned int final_time;
  int usar_simbolos = TRUE;
  int ret = TRUE;

/* Obtengo el path del IDB actual */
  get_actual_idb_name ( file1 );

/* Pregunto al usuario donde esta el file que quiero comparar */
  file = my_askfile ( FALSE , "*.idb" , "Choose the file to compare" );

/* Si tengo el nombre del segundo file */
  if ( file != NULL )
  {
  /* Hago una copia del path completo del idb */
    qstrncpy ( current_path , file1 , QMAXPATH );

  /* Busco la barra invertida */
    if ( strrchr ( current_path , '\\' ) != NULL )
    {
    /* Cierro el string donde empieza la ultima barra */
      * ( strrchr ( current_path , '\\' ) ) = '\0';
    }

  /* Seteo el nombre del archivo por default */
    qsnprintf ( log_file , QMAXPATH , "%s\\results.txt" , current_path );

  /* Mensaje al usuario con las opciones a comparar */
    if ( my_AskUsingForm ( files_a_comparar , log_file , &usar_simbolos ) == TRUE )
    {
    /* Tomo el tiempo actual */
      initial_time = GetTickCount ();

    /* Me quedo con el nombre del segundo file */
      qstrncpy ( file2 , file , strlen ( file ) );

    /* Reemplazo las extenciones ".idb" por ".ana" */
      change_extension ( file1 , "ana" );
      change_extension ( file2 , "ana" );

    /* Comparo el analisis de los 2 archivos */
      if ( comparar_files ( file1 , file2 , log_file , usar_simbolos ) == FALSE )
      {
      /* Mensaje de ERROR */
        MessageBox ( NULL , "cannot load analysis files" , "ERROR" , MB_ICONERROR | MB_TOPMOST );
    
      /* Salgo */
        return ( FALSE );
      }

    /* Tomo el tiempo final */
      final_time = GetTickCount ();

    /* Mensaje al usuario */
      my_msg ( "elapsed time: %u.%u sec.\n" , ( final_time - initial_time ) / 1000 , ( final_time - initial_time ) % 1000 );

    /* Armo los pares de funciones matcheadas en listas */
      armar_resultados ();

    /* Guardo los resultados */
      my_msg ( "saving result file ...\n" );
      guardar_resultados ( file1 , file2 );

    /* Muestro los resultados al usuario */
      mostrar_resultados ( file1 , file2 );
    }
  /* Si el usuario apreto escape */
    else
    {
    /* Salgo */
      return ( FALSE );
    }
  }
/* Si el usuario NO eligio ningun file */
  else
  {
  /* Mensaje al usuario */
    my_msg ( "Canceled operation\n" );

  /* Salgo */
    return ( FALSE );
  }

  return ( ret );
}

/****************************************************************************/ 

int comparar_funciones ( int comparar_por_pares )
{
  char file1 [ QMAXPATH ];
  char file2 [ QMAXPATH ];
  char *file;
  int ret = FALSE;

/* Obtengo el path del IDB actual */
  get_actual_idb_name ( file1 );

/* Pregunto al usuario donde esta el file que quiero comparar las funciones */
  file = my_askfile ( FALSE , "*.idb" , "Choose the compared idb" );

/* Si tengo el nombre del segundo file */
  if ( file != NULL )
  {
  /* Me quedo con el nombre del segundo file */
    qstrncpy ( file2 , file , strlen ( file ) );

  /* Reemplazo las extenciones ".idb" por ".ana" */
    change_extension ( file1 , "ana" );
    change_extension ( file2 , "ana" );

  /* Llamo a la funcion encargada de diffear funciones */
    diffear_funciones ( comparar_por_pares , file1 , file2 );

  /* Retorno OK */
    ret = TRUE;
  }

  return ( ret );
}

/****************************************************************************/ 
/****************************************************************************/

/* Funciones */

int analizar_programa ( int analizar_undefined_functions )
{
  List direcciones_iniciales;
  Funcion *funcion;
  unsigned int address_inicial;
  unsigned int cantidad_funciones;
  unsigned int referencia_padre;
  unsigned int decena;
  unsigned int pos;
  unsigned int cont;
  func_t *f;
  int ret = TRUE;

/* Cantidad de funciones que tiene el programa */
  cantidad_funciones = get_func_qty ();

/* Decena para usarla de divisor */
  decena = cantidad_funciones / 10;

/* Imprimo la cantidad de funciones detectadas */
  my_msg ( "detected functions = %i\n" , cantidad_funciones );

/* Relevo todas las funciones del programa */
  for ( pos = 0 ; pos < cantidad_funciones ; pos ++ )
  {
  /* Levanto la siguiente funcion */
    f = getn_func ( pos );

  /* Creo una nueva estructura para la funcion */
    funcion = ( Funcion * ) malloc ( sizeof ( Funcion ) );

  /* Seteo la direccion de la funcion */
    funcion -> address = f -> startEA;

  /* Agrego la direccion de la funcion en la lista */
    indice_funciones.Add ( ( void * ) funcion -> address );

  /* Agrego la funcion a la lista */
    funciones.Add ( funcion );
  }

/* Analizo todas las funciones del programa */
  for ( pos = 1 ; pos <= funciones.Len () ; pos ++ )
  {
  /* Si paso el 10 porciento mas */
    if ( pos == 1 || ( pos % decena ) == 0 )
    {
    /* Porcentaje al usuario */
      my_msg ( "analazing %i%%...\n" , ( pos / decena ) * 10 );
    }

  /* Levanto la siguiente funcion */
    funcion = ( Funcion * ) funciones.Get ( pos - 1 );

  /* Relevo todos los datos de la funcion */
    analizar_funcion ( funcion -> address , funcion );
  }

////////////////////////////

/* Si tengo que analizar las funciones NO encontradas por IDA */
  if ( analizar_undefined_functions == TRUE )
  {
  /* Recorro todas las referencias padre de codigo NO asociado a funciones */
    for ( pos = 0 ; pos < referencias_undefined.Len () ; pos ++ )
    {
    /* Levanto la siguiente referencia */
      referencia_padre = ( unsigned int ) referencias_undefined.Get ( pos );

    /* Si encontre una funcion */
      if ( get_funciones_undefined ( 0 , referencia_padre , direcciones_iniciales ) == TRUE )
      {
      /* Recorro la lista de funciones detectadas */
        for ( cont = 0 ; cont < direcciones_iniciales.Len () ; cont ++ )
        {
        /* Levanto la siguiente direccion */
          address_inicial = ( unsigned int ) direcciones_iniciales.Get ( cont );

        /* Si la funcion NO esta registrada */
          if ( undefined_functions.Find ( ( void * ) address_inicial ) == FALSE )
          {
          /* Agrego la funcion a la lista */
            undefined_functions.Add ( ( void * ) address_inicial );

          /* Mensaje al usuario */
//            my_msg ( "U_FUNCTION: %x\n" , address_inicial );
          }
        }
      }
    }

  /* Mensaje al usuario */
    my_msg ( "undefined functions detected = %i\n" , undefined_functions.Len () );

  /* Recorro todas las funciones UNDEFINEDs */
    for ( pos = 0 ; pos < undefined_functions.Len () ; pos ++ )
    {
    /* Levanto la siguiente direccion */
      address_inicial = ( unsigned int ) undefined_functions.Get ( pos );

    /* Creo una nueva estructura para la funcion */
      funcion = ( Funcion * ) malloc ( sizeof ( Funcion ) );

    /* Seteo la direccion de la funcion */
      funcion -> address = address_inicial;

    /* Si la funcion undefined NO esta en la lista */
      if ( get_estructura_funcion ( funciones , funcion -> address ) == NULL )
      {
      /* Agrego la funcion a la lista */
        funciones.Add ( funcion );
      }
//      else
//      {
//        my_msg ( "funcion undefined %x mal definida\n" , funcion -> address );
//      }   

    /* Relevo todos los datos de la funcion */
      analizar_funcion ( funcion -> address , funcion );

    /* Seteo el nombre de la funcion */
      qsnprintf ( funcion -> name , NAME_LEN , "sub_%x_undefined" , funcion -> address );
    }
  }

////////////////////////////

/* Actualizo todos los checksums de los basic blocks padres de las funciones */
  for ( pos = 0 ; pos < funciones.Len () ; pos ++ )
  {
  /* Levanto la siguiente funcion */
    funcion = ( Funcion * ) funciones.Get ( pos );

  /* Actualizo los basic blocks para esta funcion */
    actualizar_checksum_basic_blocks_padres ( indice_funciones , funciones , funcion );
  }

  return ( ret );
}

/****************************************************************************/ 

int analizar_funcion ( unsigned int address , Funcion *funcion )
{
  unsigned int cont;
  int ret = FALSE;

/* Si la estructura no es NULL */
  if ( funcion != NULL )
  {
  /* Direccion de la funcion */
    funcion -> address = address;

  /* Direccion de la funcion equivalente en file2 */
    funcion -> address_equivalente = BADADDR;

  /* Inicializo el nombre de la funcion */
    qstrncpy ( funcion -> name , "" , 256 );

  /* Nombre de la funcion */
    get_func_name ( funcion -> address , funcion -> name , 255 );

  /* Inicializo el nombre demangleado de la funcion */
    qstrncpy ( funcion -> demangled_name , "" , 256 );

  /* Demangleo el nombre de la funcion */
    demangle_name ( funcion -> demangled_name , 1024 , funcion -> name , 0x0ea3be67 );

  /* Inicializo la ecuacion que representa el grafo de la funcion */
    funcion -> graph_ecuation = NULL;

  /* Inicializo el flag de funcion identica, patcheada */
    funcion -> identica = FALSE;
    funcion -> patcheada = FALSE;

  /* Analizo todos los basic blocks de la funcion */
//    my_msg ( "procesing function %x\n" , funcion -> address );
    ret = identificar_basic_blocks ( funcion , basic_blocks , 0 , funcion -> address , funcion -> address );

  /* Suprimo todos los basic blocks que tienen longitud CERO */
  /* Son los basic blocks que conectan uno con otro a traves de un JUMP */
    suprimir_basic_blocks_vacios ( funcion , basic_blocks );

  /* Compacto todos los basic blocks unidos por UNA SOLA FLECHA */
    //nicolas7
    compactar_basic_blocks ( funcion , basic_blocks );

  /* Longitud de la funcion */
    funcion -> longitud = calcular_longitud_funcion ( basic_blocks );

  /* Calculo los checksums de la funcion */
//    funcion -> checksum = calcular_checksum_funcion ( basic_blocks );
    calcular_checksum_funcion ( basic_blocks , &funcion -> checksum , &funcion -> checksum_real );

  /* Seteo la cantidad de llamados que tiene esta funcion por llamados directos */
    funcion -> cantidad_referencias_padre = 0;
    funcion -> basic_blocks_padres = NULL;

  /* Inicializo las referencias padre a traves de indirecciones por vtables */
    funcion -> referencias_padre_x_vtable = new ( List );

  /* Averiguo todas las referencias padre */
    get_referencias_padre ( funcion );

  /* Calculo la cantidad de basic blocks que tiene la funcion */
    funcion -> cantidad_basic_blocks = basic_blocks.Len ();

  /* Creo el espacio para guardar todos los basic blocks */
    funcion -> basic_blocks = ( Basic_Block ** ) malloc ( sizeof ( Basic_Block * ) * funcion -> cantidad_basic_blocks );

  /* Copio todos los basic blocks ahi */
    for ( cont = 0 ; cont < basic_blocks.Len () ; cont ++ )
    {
    /* Asigno el proximo basic block */
      funcion -> basic_blocks [ cont ] = ( Basic_Block * ) basic_blocks.Get ( cont );
    }

  /* Seteo la cantidad de referencias que hay */
    funcion -> cantidad_referencias_hijas = calcular_cantidad_hijos ( funcion );

  /* Calculo la cantidad de conexiones internas que tiene la funcion */
    funcion -> conexiones_internas = calcular_cantidad_conexiones_internas ( funcion );

  /* Seteo la profundidad hacia abajo de todos los basic blocks */
    setear_profundidad_hacia_abajo ( 0 , funcion , funcion -> basic_blocks [ 0 ] );

  /* Seteo la profundidad hacia arriba de todos los basic blocks */
    setear_profundidad_hacia_arriba ( -1 , funcion , NULL );

  /* Calculo el peso de la funcion */
    funcion -> peso = setear_peso_a_basic_blocks ( 0 , funcion , funcion -> basic_blocks [ 0 ] );

  /* Marco todos los basic blocks con IDs */
    poner_ids_a_basic_blocks ( 0 , funcion , funcion -> basic_blocks [ 0 ] );

    Basic_Block *basic_block;
    for ( cont = 0 ; cont < funcion -> cantidad_basic_blocks ; cont ++ )
    {
      basic_block = funcion -> basic_blocks [ cont ];

      if ( basic_block -> id == -1 )
      {
        my_msg ( "funcion %x, bb %x = -1\n" , funcion -> address , basic_block -> addr_inicial );
      }
    }

//    my_msg ( "%x pesa %u\n" , funcion -> address , funcion -> peso );
//    my_msg ( "%x tiene %i basic blocks, checksum = %u, referencias_padre = %i, conexiones_internas = %i, hijos = %i\n" , funcion -> address , funcion -> cantidad_basic_blocks , funcion -> checksum , funcion -> cantidad_referencias_padre , funcion -> conexiones_internas , funcion -> cantidad_referencias_hijas );
  }

  return ( ret );
}

/****************************************************************************/ 

int identificar_basic_blocks ( Funcion *funcion , List &basic_blocks , unsigned int nivel , unsigned int addr_inicial , unsigned int addr_actual )
{
  char mnemonico [ 256 + 1 ];
  List *funciones_en_vtable;
  List referencias_from;
  Basic_Block *basic_block_actual;
  unsigned int funcion_hija;
  unsigned int referencia_hija;
  unsigned int referencia_hija2;
  unsigned int len_instruccion;
  unsigned int len_basic_block;
  unsigned int len_mnemonico;
  unsigned int longitud;
  unsigned int mini_checksum;
  unsigned int checksum;
  unsigned int conditional_checksum;
  unsigned int cont;
  int levantar_proxima_instruccion;
  int fin_basic_block = FALSE;
  int jump_detectado = FALSE;
  int ret = TRUE;
  char *str;

/* Si es el primer llamado a la funcion */
  if ( nivel == 0 )
  {
  /* Inicializo la lista de basic blocks */
    basic_blocks.Clear ();
  }

/* Obtengo el basic block actual */
  basic_block_actual = get_basic_block ( basic_blocks , addr_actual );

/* Si es el primer acceso al basic block */
  if ( basic_block_actual == NULL )
  {
  /* Agrego el primer basic block a la lista */
    basic_block_actual = ( Basic_Block * ) malloc ( sizeof ( Basic_Block ) );

  /* Seteo el inicio del basic block */
    basic_block_actual -> addr_inicial = addr_actual;

  /* Seteo las profundidades */
    basic_block_actual -> profundidad = MAX_INT;
    basic_block_actual -> profundidad2 = 0xffffffff;

  /* Inicializo el peso */
    basic_block_actual -> peso = 0;

  /* Inicializo la posicion en el file de desensamblado */
    basic_block_actual -> pos_file_disasm = 0;

  /* Creo una lista PERSISTENTE para guardar las conexiones con otros basic blocks */
    basic_block_actual -> basic_blocks_hijos = new ( List );

  /* Creo una lista para guardar las funciones a las que llama */
    basic_block_actual -> cantidad_referencias = 0;
    basic_block_actual -> funciones_hijas = new ( List );

  /* Creo una lista PERSISTENTE para guardar las conexiones DEBILES ( vtables ) */
    basic_block_actual -> ptr_funciones_hijas = new ( List );

  /* Seteo un flag para usarlo en la comparacion */
    basic_block_actual -> visitado = FALSE;

  /* Inicializo el ID del basic block */
    basic_block_actual -> id = -1;

  /* Inicializo la lista que encadena basic blocks simples */
    basic_block_actual -> cadena_basic_blocks = new ( List );

  /* Agrego el basic block a la lista */
    basic_blocks.Add ( ( void * ) basic_block_actual );
  }

/* Cantidad de instrucciones de contiene el basic block */
  longitud = 0;

/* Inicializo la cantidad de bytes que va a ocupar el basic block */
  len_basic_block = 0;

/* Inicializo el checksum del basic block */
  checksum = 0;

//  my_msg ( "procesing basic block %x\n" , basic_block_actual -> addr_inicial );

/* Mientras haya mas instrucciones */
  do
  {
  /* Flag que utilizo para realizar una excepcion cuando un basic block continua en otro */
    levantar_proxima_instruccion = TRUE;

  /* Incremento la cantidad de instrucciones que contiene el basic block */
    longitud ++;

  /* Averiguo la longitud en bytes de la instruccion */
    len_instruccion = get_item_size ( addr_actual );

  /* Incremento la longitud en bytes del basic block */
    len_basic_block += len_instruccion;

  /* Si la instruccion referencia hacia algo externo a la funcion */
    if ( is_call ( addr_actual , &funcion_hija ) == TRUE )
    {
    /* Si la referencia es hacia una funcion del programa */
      if ( is_llamado_a_funcion ( addr_actual , &referencia_hija ) == TRUE )
      {
      /* Incremento la cantidad de referencias del basic block */
        basic_block_actual -> cantidad_referencias ++;

      /* Agrego la direccion de la funcion a la lista de llamados del basic block */
        basic_block_actual -> funciones_hijas -> Add ( ( void * ) referencia_hija );

      /* Incremento el checksum en 0x100000 */
        checksum += 0x100000;
      }
    /* Si la referencia es hacia una funcion importada */
      else
      {
      /* Incremento el checksum en 0x0f0000 */
        checksum += 0x0f0000;
      }
    }
  /* Si es una JUMP TABLE */
    else if ( ( get_referencias_fcode_from ( addr_actual , referencias_from ) == TRUE ) && ( referencias_from.Len () > 1 ) )
    {
//      my_msg ( "JUMP TABLE: %x\n" , addr_actual );
      //nicolas8

    /* Agrego todas las referencias hijas al basic block */
      basic_block_actual -> basic_blocks_hijos -> Append ( &referencias_from );

    /* Marco el fin del basic block */
      fin_basic_block = TRUE;

    /* Recorro todas las conexiones */
      for ( cont = 0 ; cont < basic_block_actual -> basic_blocks_hijos -> Len () ; cont ++ )
      {
      /* Levanto la siguiente conexion */
        referencia_hija = ( unsigned int ) basic_block_actual -> basic_blocks_hijos -> Get ( cont );

      /* Si es la primera vez que apunto a este basic block */
        if ( get_basic_block ( basic_blocks , referencia_hija ) == NULL )
        {
        /* Avanzo por la siguiente conexion */
          identificar_basic_blocks ( funcion , basic_blocks , nivel + 1 , addr_inicial , referencia_hija );
        }
      }
    }
  /* Si es una referencia por datos */
    else if ( is_referencia_externa_por_dato ( addr_actual ) == TRUE )
    {
    /* Si es un puntero a funcion */
      if ( is_ptr_a_funcion ( addr_actual , &referencia_hija ) == TRUE )
      {
//        my_msg ( "ptr funcion: %x\n" , addr_actual );

      /* Incremento la cantidad de referencias del basic block */
        basic_block_actual -> cantidad_referencias ++;

      /* Agrego la direccion de la funcion a la lista de llamados del basic block */
        basic_block_actual -> funciones_hijas -> Add ( ( void * ) referencia_hija );

      /* Incremento el checksum en 0x80000 */
        checksum += 0x80000;
      }
    /* Si es una VTABLE */
      else if ( is_ptr_vtable ( addr_actual ) == TRUE )
      {
//        my_msg ( "vtable: %x\n" , addr_actual );

      /* Obtengo la lista de funciones pertenecientes a la VTABLE */
        funciones_en_vtable = get_funciones_de_vtable ( addr_actual );

      /* Agrego las funciones de la vtable como HIJAS */
        basic_block_actual -> ptr_funciones_hijas -> Append ( funciones_en_vtable );

      /* Incremento el checksum en 0x10000 */
      /* Sumo el mismo checksum aque bajo ya que IDA, a veces, no reconoce funciones */
        checksum += 0x10000;
      }
    /* Si la referencia es por un "jmp" a codigo o por data externa a la funcion */
      else
      {
      /* Incremento el checksum en 0x10000 */
        checksum += 0x10000;
      }
    }
    else
    {
    /* Si la instruccion referencia hacia otro basic block */
      if ( is_referencia_interna ( addr_inicial , addr_actual , &referencia_hija ) == TRUE )
      {      
      /* Obtengo la lista de referencias hijas */
//        get_referencias_fcode_from ( addr_actual , referencias_from );

      /* Si el basic block tiene mas de una salida */
        if ( get_next_instruction ( addr_inicial , addr_actual , &referencia_hija2 ) == TRUE )
        {
        /* Averiguo el mnemonico que termina el basic block */
        /* Tengo que hacer esto porque los saltos son relativos */
          get_instruction ( addr_actual , mnemonico , 16 );

        /* Busco un espacio en la instruccion */
          str = strchr ( mnemonico , ' ' );

        /* Trunco la instruccion donde encuentro un espacio */
          if ( str != NULL )
          {
          /* Reemplazo el espacio por un cero */
            *str = '\0';
          }

        /* Averiguo la longitud de la instruccion */
          len_mnemonico = strlen ( mnemonico );

        /* Checksum ASCII de la instruccion que bifurca */
          conditional_checksum = 0;

        /* Sumo todos los bytes que representan el mnemonico de la instruccion */
          for ( cont = 0 ; cont < len_mnemonico ; cont ++ )
          {
          /* Sumo el siguiente byte a la instruccion */
            conditional_checksum += ( unsigned int ) mnemonico [ cont ];
          }

        /* Agrego el checksum de la instruccion al total del basic block */
          checksum += conditional_checksum;

        /* Descuento la longitud en bytes de la instruccion */
          len_basic_block -= len_instruccion;

        /* Sumo solo la longitud ASCII del mnemonico condicional */
          len_basic_block += len_mnemonico;

        /* Marco el fin del basic block */
          fin_basic_block = TRUE;
        }
      /* Si es un JUMP incondicional */
        else
        {
        /* Marco el fin del basic block */
          fin_basic_block = TRUE;

        /* Si el JUMP NO apunta a si mismo ( increible pero hay ;-) ) */
          if ( addr_actual != referencia_hija )
          {
          /* Descuento el JUMP como instruccion */
            longitud --;

          /* Descuento la longitud en bytes de la instruccion */
            len_basic_block -= len_instruccion;

          /* Marco el flag de JUMP detectado */
            jump_detectado = TRUE;
          }
        }

      /* Si es el fin del basic block */
        if ( fin_basic_block == TRUE )
        {
        /* Si es la primera vez que apunto a este basic block */
          if ( get_basic_block ( basic_blocks , referencia_hija ) == NULL )
          {
          /* Si pude procesar este nuevo basic block referenciado */
            if ( identificar_basic_blocks ( funcion , basic_blocks , nivel + 1 , addr_inicial , referencia_hija ) == TRUE )
            {
            /* Seteo el primer basic block hijo */
              basic_block_actual -> basic_blocks_hijos -> Add ( ( void * ) referencia_hija );
            }
            else
            {
              my_msg ( "??? %x -> %x\n" , addr_actual , referencia_hija );
            }
          }
          else
          {
          /* Seteo el primer basic block hijo */
            basic_block_actual -> basic_blocks_hijos -> Add ( ( void * ) referencia_hija );
          }
        }
      }
      else
      {
      /* Inicializo el sumador de bytes por instruccion */
        mini_checksum = 0;

      /* Sumo todos los bytes de la instruccion */
        for ( cont = 0 ; cont < len_instruccion ; cont ++ )
        {
        /* Sumo la posicion en el basic block + el siguiente byte a la instruccion */
          mini_checksum += ( unsigned int ) get_byte ( addr_actual + cont );
        }

      /* Sumo al checksum la posicion en el basic block x 1000 */
        checksum += mini_checksum;
//        checksum += mini_checksum * ( 1000 * longitud );
      }
    }

  /* Obtengo la proxima instruccion */
    if ( ( levantar_proxima_instruccion == TRUE ) && ( get_next_instruction ( addr_inicial , addr_actual , &referencia_hija ) == TRUE ) )
    {
    /* Si la proxima instruccion es en otro basic block */
      if ( ( fin_basic_block == TRUE ) || ( is_inicio_basic_block ( funcion , basic_blocks , referencia_hija ) == TRUE ) )
      {
//      /* Si la proxima instruccion es en una funcion */
//        if ( is_funcion ( referencia_hija ) == TRUE )
//        {
//          my_msg ( "posible conexion con funcion: %x -> %x\n" , addr_actual , referencia_hija );
//        }

      /* Si es la primera vez que apunto a este basic block */
        if ( get_basic_block ( basic_blocks , referencia_hija ) == NULL )
        {
        /* Si NO pude procesar el basic block referenciado inmediatamente */
          if ( identificar_basic_blocks ( funcion , basic_blocks , nivel + 1 , addr_inicial , referencia_hija ) == FALSE )
          {
            my_msg ( "???? %x -> %x\n" , addr_actual , referencia_hija );

          /* Anulo la referencia */
            referencia_hija = NULL;
          }
        }

      /* Agrego la nueva conexion */
        basic_block_actual -> basic_blocks_hijos -> Add ( ( void * ) referencia_hija );

      /* Aca finaliza el basic block actual porque hubo una bifurcacion */
        break;
      }
    }
  }
/* Obtengo la siguiente instruccion */
  while ( ( levantar_proxima_instruccion == FALSE ) || ( get_next_instruction ( addr_inicial , addr_actual , &addr_actual ) == TRUE ) );

/* Cierro el basic block */
  basic_block_actual -> addr_final = addr_actual + len_instruccion;
  basic_block_actual -> longitud = longitud;
  basic_block_actual -> longitud_en_bytes = len_basic_block;
  basic_block_actual -> checksum = checksum;

/* Agrego la direccion del basic block */
  basic_block_actual -> cadena_basic_blocks -> Add ( ( void * ) basic_block_actual -> addr_inicial );

/* Agrego la longitud del basic block */
  basic_block_actual -> cadena_basic_blocks -> Add ( ( void * ) longitud );

/* Si el basic block tiene CERO instrucciones y no tiene un JUMP incondicional */
  if ( ( basic_block_actual -> longitud == 0 ) && ( jump_detectado == FALSE ) )
  {
  /* Elimino el basic block de la lista */
    basic_blocks.DeleteElement ( ( void * ) basic_block_actual );

  /* Retorno ERROR, no pude procesar el basic block */
    ret = FALSE;
  }

  return ( ret );
}

/****************************************************************************/ 

int compactar_basic_blocks ( Funcion *funcion , List &basic_blocks )
{
  List basic_blocks_padres;
  Basic_Block *basic_block_padre;
  Basic_Block *basic_block_hijo;
  unsigned int cont, cont2;
  int ret = TRUE;

/* Recorro todos los basic blocks */
  for ( cont = 0 ; cont < basic_blocks.Len () ; cont ++ )
  {
  /* Levanto el siguiente basic block */
    basic_block_padre = ( Basic_Block * ) basic_blocks.Get ( cont );

  /* Si este basic block tiene una sola salida */
    if ( basic_block_padre -> basic_blocks_hijos -> Len () == 1 )
    {
    /* Busco el basic block hijo */
      basic_block_hijo = get_basic_block ( basic_blocks , ( unsigned int ) basic_block_padre -> basic_blocks_hijos -> Get ( 0 ) );

    /* Si el basic block NO se llama a si mismo */
      if ( basic_block_padre != basic_block_hijo )
      {
      /* Si el basic block hijo tiene un solo padre */
        if ( get_cantidad_basic_blocks_padres_from_list ( funcion , basic_block_hijo , basic_blocks ) == 1 )
        {
        /* Si el basic block hijo tiene alguna instruccion */
          if ( basic_block_hijo -> longitud > 0 )
          {
          /* Agrego la direccion del basic block hijo */
            basic_block_padre -> cadena_basic_blocks -> Add ( ( void * ) basic_block_hijo -> addr_inicial );

          /* Agrego la longitud del basic block hijo */
            basic_block_padre -> cadena_basic_blocks -> Add ( ( void * ) basic_block_hijo -> longitud );

          /* Absorvo la longitud del hijo */
            basic_block_padre -> longitud += basic_block_hijo -> longitud;

          /* Absorvo el checksum del hijo */
            basic_block_padre -> checksum += basic_block_hijo -> checksum;

          /* Absorvo la cantidad de llamados a funciones */
            basic_block_padre -> cantidad_referencias += basic_block_hijo -> cantidad_referencias;

          /* Absorvo los llamados a las funciones hijas */
            for ( cont2 = 0 ; cont2 < basic_block_hijo -> funciones_hijas -> Len () ; cont2 ++ )
            {
              basic_block_padre -> funciones_hijas -> Add ( basic_block_hijo -> funciones_hijas -> Get ( cont2 ) );
            }

          /* Elimino la unica conexion del basic block padre */
            basic_block_padre -> basic_blocks_hijos -> Clear ();

          /* Absorvo las conexiones del basic block hijo */
            basic_block_padre -> basic_blocks_hijos -> Append ( basic_block_hijo -> basic_blocks_hijos );

          /* Elimino el basic block hijo */
            basic_blocks.DeleteElement ( basic_block_hijo );

          /* Arranco de vuelta la busqueda */
            cont = ( int ) -1;
          }
        }
      }
    }
  }

  return ( ret );
}

/****************************************************************************/ 

int suprimir_basic_blocks_vacios ( Funcion *funcion , List &basic_blocks )
{
  Basic_Block *basic_block_padre;
  Basic_Block *basic_block;
  unsigned int cont1, cont2, cont3;
  int ret = TRUE;

/* Recorro todos los basic blocks */
  for ( cont1 = 0 ; cont1 < basic_blocks.Len () ; cont1 ++ )
  {
  /* Levanto el proximo basic block */
    basic_block = ( Basic_Block * ) basic_blocks.Get ( cont1 );

  /* Si el basic block tiene CERO instrucciones */
    if ( basic_block -> longitud == 0 )
    {
    /* Recorro todos los basic blocks */
      for ( cont2 = 0 ; cont2 < basic_blocks.Len () ; cont2 ++ )
      {
      /* Levanto el proximo basic block */
        basic_block_padre = ( Basic_Block * ) basic_blocks.Get ( cont2 );

      /* Recorro todas las conexiones hijas del basic block */
        for ( cont3 = 0 ; cont3 < basic_block_padre -> basic_blocks_hijos -> Len () ; cont3 ++ )
        {
        /* Si la conexion apunta a este basic block */
          if ( ( unsigned int ) basic_block_padre -> basic_blocks_hijos -> Get ( cont3 ) == basic_block -> addr_inicial )
          {
          /* Salteo la conexion y conecto padre con nieto */
            basic_block_padre -> basic_blocks_hijos -> Set ( cont3 , basic_block -> basic_blocks_hijos -> Get ( 0 ) );
          }
        }
      }

    /* Elimino el basic block */
      basic_blocks.Delete ( cont1 );

    /* Decremento la cantidad de basic blocks para equilibrar la extraccion */
      cont1 --;
    }
  }

  return ( ret );
}

/****************************************************************************/ 

int search_value_x_dicotomic_style ( List &valores , unsigned int valor )
{
  unsigned int cota_minima;
  unsigned int cota_maxima;
  unsigned int pos_actual;
  unsigned int valor_actual;
  int ret = FALSE;

/* Seteo la posicion minima */
  cota_minima = 0;

/* Seteo la posicion maxima */
  cota_maxima = valores.Len () - 1;

/* Mientras no se junten la minima con la maxima */
  while ( cota_minima <= cota_maxima )
  {
  /* Me posiciono en la mitad de las 2 cotas */
    pos_actual = ( cota_minima + cota_maxima ) / 2;

  /* Leo el valor correspondiente a la posicion */
    valor_actual = ( unsigned int ) valores.Get ( pos_actual );

  /* Si es el valor que estaba buscando */
    if ( valor_actual == valor )
    {
    /* Retorno OK */
      ret = TRUE;

    /* Corto la busqueda */
      break;
    }

  /* Si el valor actual es mas chico que el valor que estoy buscando */
    if ( valor_actual < valor )
    {
    /* Muevo la cota minima una posicion mas que la actual */
      cota_minima = pos_actual + 1;
    }
  /* Si el valor actual es mas grande que el valor que estoy buscando */
    else
    {
      cota_maxima = pos_actual - 1;
    }
  }

  return ( ret );
}

/****************************************************************************/ 

int get_next_instruction ( unsigned int addr_inicial , unsigned int addr_actual , unsigned int *addr_siguiente )
{
  unsigned int funcion_padre;
  unsigned int address;
  unsigned int faddress;
  int ret = FALSE;

/* Averiguo la siguiente referencia */
  address = get_first_cref_from ( addr_actual );
  faddress = get_first_fcref_from ( addr_actual );

/* Si esta direccion es alcanzada por un salto del programa */
  if ( address == faddress )
  {
  /* Levanto la otra referencia de la instruccion */
    address = get_next_cref_from ( addr_actual , address );
  }

/* Si me devolvio una direccion */
  if ( address != BADADDR )
  {
  /* Retorno la direccion de la proxima instruccion */
    *addr_siguiente = address;

  /* Retorno OK */
    ret = TRUE;
  }

  return ( ret );
}

/****************************************************************************/ 

int is_fin_basic_block ( unsigned int addr_inicial , unsigned int address )
{
  unsigned int funcion_padre;
  unsigned int address2;
  int ret = FALSE;

/* Leo la primera referencia por salto desde la instruccion */
  address2 = get_first_fcref_from ( address );

/* Leo la funcion padre a la que llama esta */
  if ( get_funcion_padre ( address2 , &funcion_padre ) == TRUE )
  {
  /* Si esta dentro de la misma funcion */
    if ( addr_inicial == funcion_padre )
    {
    /* Retorno OK */
      ret = TRUE;
    }
  }

  return ( ret );
}

/****************************************************************************/ 

int is_referencia_interna ( unsigned int addr_inicial , unsigned int address , unsigned int *address_referenciada )
{
  unsigned int funcion_padre;
  unsigned int address2;
  int ret = FALSE;

/* Leo la primera referencia desde esta instruccion */
  address2 = get_first_fcref_from ( address );

/* Leo a que funcion pertenece esta direccion */
  if ( address2 != BADADDR )
  {
  /* Retorna la direccion apuntada */
    *address_referenciada = address2;

  /* Retorno OK */
    ret = TRUE;
  }

  return ( ret );
}

/****************************************************************************/ 

int is_referencia_externa_por_codigo ( unsigned int address )
{
  xrefblk_t xb;
  int ret = FALSE;

/* Si tiene una referencia por codigo */
  if ( xb.first_from ( address , XREF_ALL ) == TRUE )
  {
  /* Mientras haya mas referencias */
    do
    {
    /* Si es una referencia por codigo */
      if ( xb.iscode == 1 )
      {
      /* Si es un CALL de algun tipo */
        if ( xb.type == fl_CN || xb.type == fl_CF )
        {
        /* Retorno OK */
          ret = TRUE;

        /* Salgo */
          break;
        }
      }
    }
    while ( xb.next_from () == TRUE );
  }

  return ( ret );
}

/****************************************************************************/ 

int is_referencia_externa_por_dato ( unsigned int address )
{
  unsigned int address2;
  int ret = FALSE;

/* Leo la primera referencia desde la instruccion */
  address2 = get_first_dref_from ( address );

/* Si esta referenciando por datos a alguna zona */
  if ( address2 != BADADDR )
  {
  /* Retorno OK */
    ret = TRUE;
  }

  return ( ret );
}

/****************************************************************************/ 

int is_call ( unsigned int address , unsigned int *address_funcion )
{
  xrefblk_t xb;
  int ret = FALSE;

/* Si tiene una referencia por codigo */
  if ( xb.first_from ( address , XREF_ALL ) == TRUE )
  {
  /* Mientras haya mas referencias */
    do
    {
    /* Si es una referencia por codigo */
      if ( xb.iscode == 1 )
      {
      /* Si es un CALL de algun tipo */
        if ( xb.type == fl_CN || xb.type == fl_CF )
        {
        /* Retorno la direccion de la funcion a la que llama */
          *address_funcion = xb.to;

        /* Retorno OK */
          ret = TRUE;

        /* Salgo */
          break;
        }
      }
    }
    while ( xb.next_from () == TRUE );
  }

  return ( ret );
}

/****************************************************************************/ 

int is_llamado_a_funcion ( unsigned int address , unsigned int *funcion_llamada )
{
  unsigned int funcion_hija;
  xrefblk_t xb;
  int ret = FALSE;

/* Si tiene una referencia */
  if ( xb.first_from ( address , XREF_ALL ) == TRUE )
  {
  /* Mientras haya mas referencias */
    do
    {
    /* Si es una referencia por codigo */
      if ( xb.iscode == 1 )
      {
      /* Si es un CALL */
        if ( xb.type == fl_CN || xb.type == fl_CF )
        {
        /* Si la referencia hija pertenece a una funcion */
          if ( get_funcion_padre ( xb.to , &funcion_hija ) == TRUE )
          {
          /* Si la referencia hija es a una funcion */
            if ( xb.to == funcion_hija )
            {
            // my_msg ( "from: %x, to: %x, code: %x, type: %x\n" , xb.from , xb.to , xb.iscode , xb.type );
            /* Funcion a la cual llama */
              *funcion_llamada = xb.to;

            /* Retorno OK */
              ret = TRUE;

            /* Corto la busqueda */
              break;
            }
          }
        }
      }
    }
    while ( xb.next_from () == TRUE );
  }

  return ( ret );
}

/****************************************************************************/ 

int is_funcion ( unsigned int address )
{
  func_t *funcion;
  int ret = FALSE;

/* Averiguo si es una funcion */
  funcion = get_func ( address );

/* Si la direccion pertenece a una funcion */
  if ( funcion != NULL )
  {
  /* Si es el principio de una funcion */
    if ( funcion -> startEA == address )
    {
    /* Retorno OK */
      ret = TRUE;
    }
  }

  return ( ret );
}

/****************************************************************************/ 

int is_inicio_basic_block ( Funcion *funcion , List &basic_blocks , unsigned int address )
{
  unsigned int funcion_padre;
  unsigned int address2;
  int ret = FALSE;

/* Si tengo en esta direccion un basic block identificado */
  if ( get_basic_block ( basic_blocks , address ) != NULL )
  {
  /* Retorno OK */
    ret = TRUE;
  }
/* Si no tengo reconocido este basic block */
  else
  {
  /* Si la direccion tiene mas de una referencia padre */
    if ( get_cantidad_referencias_padre ( funcion , address ) > 1 )
    {
    /* Retorno OK */
      ret = TRUE;
    }
  }

  return ( ret );
}

/****************************************************************************/ 

int tienen_un_mismo_padre ( Funcion *funcion1 , Funcion *funcion2 )
{
  unsigned int cont1, cont2;
  int ret = FALSE;

/* Recorro todas las referencias padre de funcion1 */
  for ( cont1 = 0 ; cont1 < funcion1 -> cantidad_referencias_padre ; cont1 ++ )
  {
  /* Si el basic block padre tiene un checksum distinto a cero */
    if ( funcion1 -> basic_blocks_padres [ cont1 ].checksum > 0 )
    {
    /* Recorro todas las referencias padre de funcion2 */
      for ( cont2 = 0 ; cont2 < funcion2 -> cantidad_referencias_padre ; cont2 ++ )
      {
     /* Si es el basic block que estoy buscando */
        if ( funcion1 -> basic_blocks_padres [ cont1 ].checksum == funcion2 -> basic_blocks_padres [ cont2 ].checksum )
        {
        /* Retorno OK */
          return ( TRUE );
        }
      }
    }
  }

  return ( ret );
}

/****************************************************************************/ 

Basic_Block *get_basic_block ( List &basic_blocks , unsigned int address )
{
  Basic_Block *basic_block = NULL;
  Basic_Block *siguiente_basic_block;
  unsigned int cont;

 /* Busco el basic block */
  for ( cont = 0 ; cont < basic_blocks.Len () ; cont ++ )
  {
  /* Levanto el siguiente basic block */
    siguiente_basic_block = ( Basic_Block * ) basic_blocks.Get ( cont );

  /* Si es el basic block que estoy buscando */
    if ( siguiente_basic_block -> addr_inicial == address )
    {
    /* Encontre el basic block */
      basic_block = siguiente_basic_block;

    /* Corto la busqueda */
      break;
    }
  }

  return ( basic_block );
}

/****************************************************************************/ 

Basic_Block *get_basic_block_from_array ( Basic_Block **basic_blocks , unsigned int len , unsigned int address )
{
  Basic_Block *basic_block = NULL;
  Basic_Block *siguiente_basic_block;
  unsigned int cont;

 /* Busco el basic block */
  for ( cont = 0 ; cont < len ; cont ++ )
  {
  /* Levanto el siguiente basic block */
    siguiente_basic_block = basic_blocks [ cont ];

  /* Si es el basic block que estoy buscando */
    if ( siguiente_basic_block -> addr_inicial == address )
    {
    /* Encontre el basic block */
      basic_block = siguiente_basic_block;

    /* Corto la busqueda */
      break;
    }
  }

  return ( basic_block );
}

/****************************************************************************/ 

unsigned int calcular_longitud_funcion ( List &basic_blocks )
{
  Basic_Block *basic_block;
  unsigned int longitud = 0;
  unsigned int cont;

/* Recorro toda la lista de basic blocks identificados */
  for ( cont = 0 ; cont < basic_blocks.Len () ; cont ++ )
  {
  /* Levanto el siguiente basic block */
    basic_block = ( Basic_Block * ) basic_blocks.Get ( cont );

  /* Sumo la cantidad de instrucciones que tiene este basic block */
    longitud += basic_block -> longitud;    
  }

  return ( longitud );
}

/****************************************************************************/ 

void calcular_checksum_funcion ( List &basic_blocks , unsigned int *checksum_con_pesos , unsigned int *checksum_real )
{
  Basic_Block *basic_block;
  Basic_Block *basic_block_hijo;
  unsigned int address_hija;
  unsigned int checksum = 0;
  unsigned int checksum2 = 0;
  unsigned int cont, cont2;
  unsigned int multiplicador = 10;

/* Recorro toda la lista de basic blocks identificados */
/* Para darle un valor a cada link e incrementarlo en la suma global */
  for ( cont = 0 ; cont < basic_blocks.Len () ; cont ++ )
  {
  /* Levanto el siguiente basic block */
    basic_block = ( Basic_Block * ) basic_blocks.Get ( cont );

  /* Recorro todos los hijos del basic block */
    for ( cont2 = 0 ; cont2 < basic_block -> basic_blocks_hijos -> Len () ; cont2 ++ )
    {
    /* Levanto el siguiente basic block hijo */
      address_hija = ( unsigned int ) basic_block -> basic_blocks_hijos -> Get ( cont2 );

    /* Obtengo el basic block */
      basic_block_hijo = get_basic_block ( basic_blocks , address_hija );

    /* Le doy un valor a la relacion entre basic blocks */
      checksum += basic_block_hijo -> checksum * multiplicador;

    /* Incremento el multiplicador para hacer diferencias entre el camino a seguir */
      multiplicador = multiplicador * 10;
    }
  }

/* Recorro toda la lista de basic blocks identificados */
  for ( cont = 0 ; cont < basic_blocks.Len () ; cont ++ )
  {
  /* Levanto el siguiente basic block */
    basic_block = ( Basic_Block * ) basic_blocks.Get ( cont );

  /* Sumo el basic block al checksum */
    checksum += basic_block -> checksum;

  /* Sumo el basic block al checksum real, util para cambios de lugar de los JUMPs */
    checksum2 += basic_block -> checksum;
  }

/* Retorno los checksums de la funcion */
  *checksum_con_pesos = checksum;
  *checksum_real = checksum2;
}

/****************************************************************************/ 

unsigned int calcular_cantidad_conexiones_internas ( Funcion *funcion )
{
  Basic_Block *basic_block;
  unsigned int conexiones_internas = 0;
  unsigned int cont;

/* Recorro todos los basic blocks de la funcion */
  for ( cont = 0 ; cont < funcion -> cantidad_basic_blocks ; cont ++ )
  {
  /* Levanto el siguiente basic block */
    basic_block = funcion -> basic_blocks [ cont ];

  /* Incremento la cantidad de conexiones internas */
    conexiones_internas += basic_block -> basic_blocks_hijos -> Len ();
  }

  return ( conexiones_internas );
}

/****************************************************************************/ 

unsigned int calcular_cantidad_hijos ( Funcion *funcion )
{
  Basic_Block *basic_block;
  unsigned int cantidad_hijos = 0;
  unsigned int cont;

/* Recorro todos los basic blocks de la funcion */
  for ( cont = 0 ; cont < funcion -> cantidad_basic_blocks ; cont ++ )
  {
  /* Levanto el siguiente basic block */
    basic_block = funcion -> basic_blocks [ cont ];

  /* Agrego la cantidad de hijos que tiene este basic block */
    cantidad_hijos += basic_block -> funciones_hijas -> Len ();
  }

  return ( cantidad_hijos );
}

/****************************************************************************/ 

unsigned int get_cantidad_referencias_padre ( Funcion *funcion , unsigned int address )
{
  unsigned int referencia_padre;
  unsigned int referencias = 0;
  unsigned int funcion_padre;

/* Leo la primera referencia hacia la funcion */
  referencia_padre = get_first_cref_to ( address );

/* Mientras haya referencias */
  while ( referencia_padre != BADADDR )
  {
  /* Incremento la cantidad de referencias */
    referencias ++;

  /* Levanto la siguiente referencia */
    referencia_padre = get_next_cref_to ( address , referencia_padre );
  }

  return ( referencias );
}

/****************************************************************************/ 

int get_referencias_padre ( Funcion *funcion )
{
  Referencia_Vtable *vtable_padre;
  func_t *funcion_padre;
  unsigned int referencia_padre;
  unsigned int referencia_hija;
  unsigned int referencia_a_vtable;
  unsigned int cantidad_referencias = 0;
  unsigned int pos_en_vtable;
  unsigned int cont;
  int ret = TRUE;

/* Busco todas las referencias por codigo y por datos */
  for ( cont = 0 ; cont < 2 ; cont ++ )
  {
  /* Si es referencia por codigo */
    if ( cont == 0 )
    {
    /* Leo la primera referencia hacia la funcion */
      referencia_padre = get_first_cref_to ( funcion -> address );
    }
  /* Si es referencia por datos */
    else
    {
    /* Leo la primera referencia hacia la funcion */
      referencia_padre = get_first_dref_to ( funcion -> address );
    }

  /* Mientras haya referencias */
    while ( referencia_padre != BADADDR )
    {
    /* Averiguo la direccion de la funcion que llama a esta */
      funcion_padre = get_func ( referencia_padre );

    /* Si pude leer info sobre la funcion */
      if ( funcion_padre != NULL )
      {
      /* Hago espacio para un basic block padre mas */
        funcion -> basic_blocks_padres = ( Basic_Block_Padre * ) realloc ( funcion -> basic_blocks_padres , ( cantidad_referencias + 1 ) * sizeof ( Basic_Block_Padre ) );

      /* Dejo en blanco el puntero a la funcion */
        funcion -> basic_blocks_padres [ cantidad_referencias ].funcion = NULL;

      /* Seteo la direccion de la funcion padre */
        funcion -> basic_blocks_padres [ cantidad_referencias ].direccion_funcion = funcion_padre -> startEA;

      /* Seteo la direccion real donde la funcion padre la llama */
        funcion -> basic_blocks_padres [ cantidad_referencias ].referencia = referencia_padre;

      /* Aumento la cantidad de referencias */
        cantidad_referencias ++;
      }
    /* Si tengo una referencia que NO pertenece a NADA */
      else
      {
      /* Si la referencia en por CODIGO */
        if ( cont == 0 )
        {
//          my_msg ( "warning: lost reference from %x\n" , referencia_padre );
//          procesar_codigo_undefined ( referencia_padre );

        /* Si la direccion NO la tengo registrada */
          if ( referencias_undefined.Find ( ( void * ) referencia_padre ) == NULL )
          {
          /* Agrego la referencia a la lista */
            referencias_undefined.Add ( ( void * ) referencia_padre );
          }
        }
      }

    /* Si es referencia por codigo */
      if ( cont == 0 )
      {
      /* Leo si hay mas referencias */
        referencia_padre = get_next_cref_to ( funcion -> address , referencia_padre );
      }
    /* Si es referencia por datos */
      else
      {
      /* Leo si hay mas referencias */
        referencia_padre = get_next_dref_to ( funcion -> address , referencia_padre );
      }
    }
  }

/* Seteo en la funcion el numero de referencias */
  funcion -> cantidad_referencias_padre = cantidad_referencias;

//////////////////////////////////////////////////////////////////////

/* Busco todas las referencias por vtables */ 
  referencia_padre = get_first_dref_to ( funcion -> address );

/* Busco todas las funciones padres de addr_destino */
  while ( referencia_padre != BADADDR )
  {
  /* Si la referencia no pertenece a una funcion */
//    if ( get_func ( referencia_padre ) == NULL )
    {
    /* Empiezo a recorrer la supuesta vtable hacia arriba */
    /* Seteo el puntero a funcion */
      pos_en_vtable = referencia_padre;

    /* Mientras el puntero no sea referenciado por alguna parte del programa */
      while ( get_first_dref_to ( pos_en_vtable ) == BADADDR )
      {
      /* Avanzo una posicion hacia arriba en la vtable */
        pos_en_vtable = pos_en_vtable - sizeof ( unsigned int );

      /* Si no es un puntero a funcion */
        if ( is_ptr_a_funcion ( pos_en_vtable , &referencia_hija ) == FALSE )
        {
        /* Si la referencia NO apunta a NULL */
        /* puntero a NULL lo cuento en al vtable */
          if ( get_long ( pos_en_vtable ) != NULL )
          {
          /* No asumo nada y desecho la posibilidad de ser una vtable */
            break;
          }
        }
      }

//      if ( pos_en_vtable == referencia_padre )
//      {
//        my_msg ( "ptr a funcion: %x\n" , pos_en_vtable );
//      }

    /* Averiguo la direccion desde donde se referencia a la VTABLE */
      referencia_a_vtable = get_first_dref_to ( pos_en_vtable );

    /* Mientras haya referencias */
      while ( referencia_a_vtable != BADADDR )
      {
      /* Averiguo a que funcion pertenece la referencia */
        funcion_padre = get_func ( referencia_a_vtable );  

      /* Si la referencia es desde una funcion */
        if ( funcion_padre != NULL )
        {
        /* Agrego la referencia */
          funcion -> referencias_padre_x_vtable -> Add ( ( void * ) funcion_padre -> startEA );  

//          my_msg ( "vtable detectada: %x -> %x\n" , referencia_a_vtable , pos_en_vtable );
        }

      /* Levanto la proxima referencia */
        referencia_a_vtable = get_next_dref_to ( pos_en_vtable , referencia_a_vtable );
      }
    }

  /* Levanto la siguiente referencia */
    referencia_padre = get_next_dref_to ( funcion -> address , referencia_padre );
  }

  return ( ret );
}

/****************************************************************************/

unsigned int get_cantidad_basic_blocks_padres_from_list ( Funcion *funcion , Basic_Block *basic_block_hijo , List &basic_blocks )
{
  Basic_Block *basic_block_padre;
  unsigned int padres = 0;
  unsigned int cont;

/* Recorro toda la lista */
  for ( cont = 0 ; cont < basic_blocks.Len () ; cont ++ )
  {
  /* Levanto el siguiente basic block */
    basic_block_padre = ( Basic_Block * ) basic_blocks.Get ( cont ); 

  /* Si el basic block es padre de este */
    if ( basic_block_padre -> basic_blocks_hijos -> Find ( ( void * ) basic_block_hijo -> addr_inicial ) == TRUE )
    {
    /* Incremento la cantidad de padres */
      padres ++;
    }
  }

  return ( padres );
}

/****************************************************************************/

int get_basic_blocks_padres ( Funcion *funcion , Basic_Block *basic_block , List &basic_blocks_padres )
{
  Basic_Block *basic_block_padre;
  unsigned int cont;
  int ret = FALSE;

/* Inicializo la lista */
  basic_blocks_padres.Clear ();

/* Recorro todos los basic blocks de la funcion */
  for ( cont = 0 ; cont < funcion -> cantidad_basic_blocks ; cont ++ )
  {
  /* Levanto el siguiente basic block */
    basic_block_padre = funcion -> basic_blocks [ cont ];

  /* Si el basic block padre tiene como hijo al basic block actual */
    if ( basic_block_padre -> basic_blocks_hijos -> Find ( ( void * ) basic_block -> addr_inicial ) == TRUE )
    {
    /* Agrego el basic block a la lista */
      basic_blocks_padres.Add ( basic_block_padre );
    }
  }

/* Si encontre algun basic block */
  if ( basic_blocks_padres.Len () > 0 )
  {
  /* Retorno OK */
    ret = TRUE;
  }

  return ( ret );
}

/****************************************************************************/

int get_basic_blocks_hijos ( Funcion *funcion , Basic_Block *basic_block , List &basic_blocks_hijos )
{
  Basic_Block *basic_block_hijo;
  unsigned int address_hija;
  unsigned int cont;
  int ret = TRUE;

/* Recorro todos los basic blocks hijos */
  for ( cont = 0 ; cont < basic_block -> basic_blocks_hijos -> Len () ; cont ++ )
  {
  /* Levanto la siguiente direccion hija */
    address_hija = ( unsigned int ) basic_block -> basic_blocks_hijos -> Get ( cont );

  /* Obtengo el basic block */
    basic_block_hijo = get_basic_block_from_array ( funcion -> basic_blocks , funcion -> cantidad_basic_blocks , address_hija );

  /* Agrego el basic block a la lista */
    basic_blocks_hijos.Add ( ( void * ) basic_block_hijo );
  }

  return ( ret );
}

/****************************************************************************/

Funcion *get_estructura_funcion ( List &funciones , unsigned int address )
{
  Funcion *funcion_a_retornar = NULL;
  Funcion *funcion;
  unsigned int cont;

/* Recorro toda la lista de funciones */
  for ( cont = 0 ; cont < funciones.Len () ; cont ++ )
  {
  /* Levanto la proxima funcion */
    funcion = ( Funcion * ) funciones.Get ( cont );

  /* Si es la funcion que estoy buscando */
    if ( funcion -> address == address )
    {
    /* Retorno OK */
      funcion_a_retornar = funcion;

    /* Corto la busqueda */
      break;
    }
  }

  return ( funcion_a_retornar );
}

/****************************************************************************/ 

Funcion *get_estructura_funcion2 ( List &indice_funciones , List &funciones , unsigned int address )
{
  Funcion *funcion = NULL;
  unsigned int pos;

/* Si la direccion de la funcion esta en el indice */
  if ( indice_funciones.GetPos ( ( void * ) address , &pos ) == TRUE )
  {
  /* Retorno la estructura de la funcion buscada */
    funcion = ( Funcion * ) funciones.Get ( pos );
  }

  return ( funcion );
}

/****************************************************************************/ 

void actualizar_checksum_basic_blocks_padres ( List &indice_funciones , List &funciones , Funcion *funcion )
{
  Funcion *funcion_padre;
  Basic_Block *basic_block;
  unsigned int cont, cont2;

/* Recorro todas las referencias padres */
  for ( cont = 0 ; cont < funcion -> cantidad_referencias_padre ; cont ++ )
  {
  /* Obtengo el padre de esta funcion */
    funcion_padre = get_estructura_funcion2 ( indice_funciones , funciones , funcion -> basic_blocks_padres [ cont ].direccion_funcion );

  /* Recorro todos los basic blocks de la funcion padre */
    for ( cont2 = 0 ; cont2 < funcion_padre -> cantidad_basic_blocks ; cont2 ++ )
    {
    /* Levanto el proximo basic block */
      basic_block = funcion_padre -> basic_blocks [ cont2 ];

    /* Si la funcion padre la llama de este basic block */
      if ( ( basic_block -> addr_inicial <= funcion -> basic_blocks_padres [ cont ].referencia ) && ( funcion -> basic_blocks_padres [ cont ].referencia < basic_block -> addr_final ) )
      {
      /* Seteo el checksum del basic block padre */
        funcion -> basic_blocks_padres [ cont ].checksum = ( ( basic_block -> addr_final - basic_block -> addr_inicial ) * 10000 ) + basic_block -> checksum;
      }
    }
  }
}

/****************************************************************************/ 

int get_funcion_padre ( unsigned int address , unsigned int *address_padre )
{
  func_t *funcion_padre;
  int ret = FALSE;

/* Averiguo a que funcion pertenece esta direccion */
  funcion_padre = get_func ( address );

/* Averiguo los limites de esta funcion */
  if ( funcion_padre != NULL )
  {
  /* Retorno la direccion padre de la funcion */
    *address_padre = funcion_padre -> startEA;

  /* Retorno OK */
    ret = TRUE;
  }

  return ( ret );
}

/****************************************************************************/ 

int is_ptr_a_funcion ( unsigned int address , unsigned int *addr_funcion )
{
  func_t *funcion;
  unsigned int address2;
  int ret = FALSE;

/* Averiguo a donde apunta */
  address2 = get_first_dref_from ( address );

/* Si esta direccion apunta a alguna direccion del programa */
  if ( address2 != BADADDR )
  {
  /* Si esta direccion es parte de una funcion */
    if ( ( funcion = get_func ( address2 ) ) != NULL )
    {
    /* Si es el inicio de la funcion */
      if ( funcion -> startEA == address2 )
      {
      /* Retorno la direccion de la funcion a la que apunta */
        *addr_funcion = address2;

      /* Retorno OK */
        ret = TRUE;
      }
    }
  }

  return ( ret );
}

/****************************************************************************/ 

int is_ptr_vtable ( unsigned int address )
{
  unsigned int funcion_apuntada;
  unsigned int vtable;
  int ret = FALSE;

/* Levanto la direccion apuntada */
  vtable = get_first_dref_from ( address );

/* Si referencia por DATA a algun lado */
  if ( vtable != BADADDR )
  {
  /* Si hay un puntero a una funcion */
    if ( is_ptr_a_funcion ( vtable , &funcion_apuntada ) == TRUE )
    {
    /* Retorno OK */
      ret = TRUE;
    }
  }

  return ( ret );
}

/****************************************************************************/

List *get_funciones_de_vtable ( unsigned int address )
{
  static List funciones_en_vtable;
  unsigned int vtable;
  unsigned int funcion_apuntada;

/* Limpio la lista */
  funciones_en_vtable.Clear ();

/* Obtengo el puntero a la vtable */
  vtable = get_first_dref_from ( address );

/* Si la vtable existe */
  if ( vtable != BADADDR )
  {
  /* Mientras haya puntero a funciones */
    while ( ( is_ptr_a_funcion ( vtable , &funcion_apuntada ) == TRUE ) || ( get_long ( vtable ) == NULL ) )
    {
//      my_msg ( "-> %x\n" , funcion_apuntada );

    /* Agrego la funcion a la lista */
      funciones_en_vtable.Add ( ( void * ) funcion_apuntada );

    /* Avanzo en la vtable */
      vtable = vtable + sizeof ( unsigned int );

    /* Si esta direccion esta referenciada */
      if ( get_first_dref_to ( vtable ) != BADADDR )
      {
      /* Dejo de procesar la vtable */
        break;
      }
    }
  }

  return ( &funciones_en_vtable );
}

/****************************************************************************/

int get_funciones_undefined ( unsigned int nivel , unsigned int address , List &direcciones_iniciales )
{
  static List inicio_basic_blocks;
  List referencias_padre;
  unsigned int referencia_padre;
  unsigned int address_referenciada;
  unsigned int address_anterior;
  unsigned int address_actual;
  unsigned int cont;
  int ret = FALSE;

/* Si estoy en el primer nivel */
  if ( nivel == 0 )
  {
  /* Reseteo la lista */
    inicio_basic_blocks.Clear ();

  /* Reinicializo la lista de funciones encontradas */
    direcciones_iniciales.Clear ();
  }
 
/* Igualo las direcciones */
  address_actual = address;

/* Avanzo hacia arriba hasta que encuentro una referencia a la direccion actual */
  while ( ( get_first_fcref_to ( address_actual ) == BADADDR ) && ( get_func ( address_actual ) == NULL ) )
  {
  /* Backupeo la direccion anterior */
    address_anterior = address_actual;

  /* Sigo avanzando hacia arriba */
    address_actual = get_first_cref_to ( address_actual );    

  /* Si llegue a una instruccion que NO es referenciada por NADIE */
    if ( address_actual == BADADDR )
    {
    /* Agrego la direccion encontrada a la lista */
      direcciones_iniciales.Add ( ( void * ) address_anterior );

    /* Retorno OK */
      return ( TRUE );
    }
  }

/* Si llegue hasta aca encontre el principio de un basic block */
//  my_msg ( "%x: SUPUESTO BB: %x - %x\n" , address , address_actual , get_first_cref_to ( address_actual ) );

/* Si este basic block no fue visitado */
  if ( inicio_basic_blocks.Find ( ( void * ) address_actual ) == FALSE )
  {
  /* Agrego el basic block a la lista */
    inicio_basic_blocks.Add ( ( void * ) address_actual );

  /* Obtengo todas las referencias padre a esta direccion */
    get_referencias_to ( address_actual , referencias_padre );

  /* Avanzo por todas las referencias padre */
    for ( cont = 0 ; cont < referencias_padre.Len () ; cont ++ )
    {
    /* Levanto la siguiente referencia */
      referencia_padre = ( unsigned int ) referencias_padre.Get ( cont );

    /* Si es un CALL */
      if ( is_call ( referencia_padre , &address_referenciada ) == TRUE )
      {
      /* Si la direccion a la que llama el CALL es la que estoy parado */
        if ( address_actual == address_referenciada )
        {
//          my_msg ( "CALL: %x --> %x\n" , referencia_padre , address_actual );

        /* Agrego la direccion encontrada a la lista */
          direcciones_iniciales.Add ( ( void * ) address_actual );

        /* Sigo recorriendo las referencias */
          continue;
        }
      }

    /* Avanzo por esta referencia */
      get_funciones_undefined ( nivel + 1 , referencia_padre , direcciones_iniciales );
    }
  }

/* Si encontre alguna funcion */
  if ( direcciones_iniciales.Len () > 0 )
  {
  /* Retorno OK */
    ret = TRUE;
  }

  return ( ret );
}

/****************************************************************************/

int get_referencias_fcode_from ( unsigned int address , List &referencias )
{
  unsigned int referencia;
  int ret = FALSE;

/* Inicializo la lista */
  referencias.Clear ();

/* Levanto la primera referencia */
  referencia = get_first_fcref_from ( address );

/* Mientras haya referencias */
  while ( referencia != BADADDR )
  {
  /* Agrego la referencia a la lista */
    referencias.Add ( ( void * ) referencia );

  /* Levanto la siguiente referencia */
    referencia = get_next_fcref_from ( address , referencia );
  }

/* Si encontre algun elemento */
  if ( referencias.Len () > 0 )
  {
  /* Retorno OK */
    ret = TRUE;
  }

  return ( ret );
}

/****************************************************************************/

int get_referencias_data_from ( unsigned int address , List &referencias )
{
  unsigned int referencia;
  int ret = FALSE;

/* Inicializo la lista */
  referencias.Clear ();

/* Levanto la primera referencia */
  referencia = get_first_dref_from ( address );

/* Mientras haya referencias */
  while ( referencia != BADADDR )
  {
  /* Agrego la referencia a la lista */
    referencias.Add ( ( void * ) referencia );

  /* Levanto la siguiente referencia */
    referencia = get_next_dref_from ( address , referencia );
  }

/* Si encontre algun elemento */
  if ( referencias.Len () > 0 )
  {
  /* Retorno OK */
    ret = TRUE;
  }

  return ( ret );
}

/****************************************************************************/

int get_referencias_to ( unsigned int address , List &referencias )
{
  unsigned int referencia;
  int ret = FALSE;

/* Inicializo la lista */
  referencias.Clear ();

/* Levanto la primera referencia */
  referencia = get_first_cref_to ( address );

/* Mientras haya referencias */
  while ( referencia != BADADDR )
  {
  /* Agrego la referencia a la lista */
    referencias.Add ( ( void * ) referencia );

  /* Levanto la siguiente referencia */
    referencia = get_next_cref_to ( address , referencia );
  }

/* Si encontre algun elemento */
  if ( referencias.Len () > 0 )
  {
  /* Retorno OK */
    ret = TRUE;
  }

  return ( ret );
}

/****************************************************************************/ 

void setear_profundidad_hacia_abajo ( int profundidad , Funcion *funcion , Basic_Block *basic_block )
{
  Basic_Block *basic_block_hijo;
  unsigned int address_hija;
  unsigned int cont;

/* Si la profundidad actual es menor que la que ya tenia */
  if ( basic_block -> profundidad > profundidad )
  {
  /* Pongo la nueva profundidad */
    basic_block -> profundidad = profundidad;
  }
/* Si la profundidad es mayor o igual */
  else
  {
  /* Dejo de avanzar por este lado */
    return;
  }

/* Recorro todos los hijos del basic block */
  for ( cont = 0 ; cont < basic_block -> basic_blocks_hijos -> Len () ; cont ++ )
  {
  /* Levanto la direccion del siguiente basic block hijo */
    address_hija = ( unsigned int ) basic_block -> basic_blocks_hijos -> Get ( cont );

  /* Levanto el siguiente basic block hijo */
    basic_block_hijo = get_basic_block_from_array ( funcion -> basic_blocks , funcion -> cantidad_basic_blocks , address_hija );

  /* Avanzo al siguiente basic block */
    setear_profundidad_hacia_abajo ( profundidad + 1 , funcion , basic_block_hijo );
  }
}

/****************************************************************************/ 

void setear_maxima_profundidad_hacia_abajo ( int profundidad , Funcion *funcion , Basic_Block *basic_block )
{
  static List basic_blocks_visitados;
  Basic_Block *basic_block_hijo;
  unsigned int address_hija;
  unsigned int cont;

/* Si estoy en el primer nivel */
  if ( profundidad == 0 )
  {
  /* Inicializo la lista */
    basic_blocks_visitados.Clear ();
  }

/* Si la profundidad actual es mayor que la del basic block actual */
  if ( basic_block -> profundidad < profundidad )
  {
  /* Pongo la nueva profundidad */
    basic_block -> profundidad = profundidad;
  }
/* Si la profundidad es mayor o igual */
  else
  {
  /* Dejo de avanzar por este lado */
    return;
  }

/* Agrego el basic block a la lista */
  basic_blocks_visitados.Add ( ( void * ) basic_block -> addr_inicial );

/* Recorro todos los hijos del basic block */
  for ( cont = 0 ; cont < basic_block -> basic_blocks_hijos -> Len () ; cont ++ )
  {
  /* Levanto la direccion del siguiente basic block hijo */
    address_hija = ( unsigned int ) basic_block -> basic_blocks_hijos -> Get ( cont );

  /* Si el basic block NO esta en la lista */
    if ( basic_blocks_visitados.Find ( ( void * ) address_hija ) == FALSE )
    {
    /* Levanto el basic block hijo */
      basic_block_hijo = get_basic_block_from_array ( funcion -> basic_blocks , funcion -> cantidad_basic_blocks , address_hija );

    /* Avanzo al siguiente basic block */
      setear_maxima_profundidad_hacia_abajo ( profundidad + 1 , funcion , basic_block_hijo );
    }
  }

/* Elimino el basic block de la lista */
  basic_blocks_visitados.DeleteElement ( ( void * ) basic_block -> addr_inicial );
}

/****************************************************************************/ 

void setear_profundidad_hacia_arriba ( int profundidad , Funcion *funcion , Basic_Block *basic_block )
{
  List basic_blocks_padres;
  Basic_Block *basic_block_padre;
  unsigned int cont;

/* Si estoy recorriendo las hojas del grafo */
  if ( profundidad == -1 )
  {
  /* Recorro todos los basic blocks */
    for ( cont = 0 ; cont < funcion -> cantidad_basic_blocks ; cont ++ )
    {
    /* Levanto el siguiente basic block */
      basic_block = funcion -> basic_blocks [ cont ];

    /* Si el basic block NO tiene hijos */
      if ( basic_block -> basic_blocks_hijos -> Len () == 0 )
      {
      /* Empiezo a procesar este camino */
        setear_profundidad_hacia_arriba ( 0 , funcion , basic_block );
      }
    }
  }
/* Si estoy recorriendo el grafo hacia arriba */
  else
  {
  /* Si la profundidad actual es menor que la que ya tenia */
    if ( basic_block -> profundidad2 > ( unsigned int ) profundidad )
    {
    /* Pongo la nueva profundidad */
      basic_block -> profundidad2 = ( unsigned int ) profundidad;
    }
  /* Si la profundidad es mayor o igual */
    else
    {
    /* Dejo de avanzar por este lado */
      return;
    }

  /* Obtengo la lista de basic blocks padres */
    get_basic_blocks_padres ( funcion , basic_block , basic_blocks_padres );

  /* Recorro la lista de basic blocks padres */
    for ( cont = 0 ; cont < basic_blocks_padres.Len () ; cont ++ )
    {
    /* Levanto el siguiente basic block padre */
      basic_block_padre = ( Basic_Block * ) basic_blocks_padres.Get ( cont );

    /* Avanzo por este camino */
      setear_profundidad_hacia_arriba ( profundidad + 1 , funcion , basic_block_padre );
    }
  }
}

/****************************************************************************/ 

unsigned int setear_peso_a_basic_blocks ( unsigned int nivel , Funcion *funcion , Basic_Block *basic_block )
{
  Basic_Block *basic_block_hijo;
  unsigned int cantidad_padres_bb;
  unsigned int cantidad_hijos_bb = 0;
  unsigned int address_hija;
  unsigned int cont;

/* Si estoy en el primer basic block de la funcion */
  if ( nivel == 0 )
  {
  /* Marco todos los basic blocks como libres */
    liberar_basic_blocks ( funcion );
  }

/* Marco el basic block como visitado */
  basic_block -> visitado = TRUE;

/* Cuento la cantidad de padres del basic block */
  cantidad_padres_bb = get_cantidad_referencias_padre ( funcion , basic_block -> addr_inicial );

/* Seteo la cantidad de hijos del basic block */
  cantidad_hijos_bb = basic_block -> basic_blocks_hijos -> Len ();

/* Seteo el peso inicial del basic block */
//  basic_block -> peso = basic_block -> profundidad;
  basic_block -> peso = ( basic_block -> funciones_hijas -> Len () * 0x100000 ) + ( cantidad_padres_bb * 0x10000 ) + ( cantidad_hijos_bb * 0x1000 ) + ( basic_block -> profundidad2 * 0x100 ) + ( basic_block -> profundidad * 0x10 ) + basic_block -> longitud;

/* Recorro todos los hijos del basic block */
  for ( cont = 0 ; cont < basic_block -> basic_blocks_hijos -> Len () ; cont ++ )
  {
  /* Levanto la direccion del siguiente basic block */
    address_hija = ( unsigned int ) basic_block -> basic_blocks_hijos -> Get ( cont );

  /* Levanto el basic block hijo 1 */
    basic_block_hijo = get_basic_block_from_array ( funcion -> basic_blocks , funcion -> cantidad_basic_blocks , address_hija );

  /* Si el basic block a visitar tiene mayor o igual profundidad que el actual */
    if ( basic_block -> profundidad <= basic_block_hijo -> profundidad )
    {
    /* Si el basic block NO fue visitado */
      if ( basic_block_hijo -> visitado == FALSE )
      {
      /* Avanzo sobre ese camino y sumo el peso de toda la rama HIJA */
        basic_block -> peso += setear_peso_a_basic_blocks ( nivel + 1 , funcion , basic_block_hijo );
      }
    /* Si el basic block ya fue visitado */
      else
      {
      /* Sumo el peso del basic block hijo */
        basic_block -> peso += basic_block_hijo -> peso;
      }
//    /* Si el basic block hijo esta a una profundidad menor que el actual */
//      else
//      {
//      /* Sumo la profundidad del basic block hijo */
//        basic_block -> peso += basic_block_hijo -> profundidad * 0x100;
//      }
    }
  }

/* Retorno el peso de la subrama */
  return ( basic_block -> peso );
}

/****************************************************************************/ 

void poner_ids_a_basic_blocks ( int id , Funcion *funcion , Basic_Block *basic_block )
{
  static int id_actual;
  List ranking_pesos;  
  Basic_Block *basic_block_hijo1;
  Basic_Block *basic_block_hijo2;
  unsigned int address_hija;
  unsigned int cont1, cont2;
  unsigned int pos;

/* Si el basic block NO tiene ID */
  if ( basic_block -> id == -1 )
  {
  /* Pongo el ID al basic block */
    basic_block -> id = id;

  /* Seteo el id actual */
    id_actual = id;
  }
/* Si ya visite este basic block */
  else
  {
    my_msg ( "???\n" );
    return;
  }

/* Duplico la lista de basic blocks hijos */
  ranking_pesos.Append ( basic_block -> basic_blocks_hijos );

/* Si tengo al menos 2 elementos */
  if ( ranking_pesos.Len () >= 2 )
  {
  /* Ordeno la lista por pesos de menor a mayor */
    for ( cont1 = 0 ; cont1 < ranking_pesos.Len () - 1 ; cont1 ++ )
    {
    /* Levanto la siguiente conexion hija */
      address_hija = ( unsigned int ) ranking_pesos.Get ( cont1 );

    /* Obtengo el basic block */
      basic_block_hijo1 = get_basic_block_from_array ( funcion -> basic_blocks , funcion -> cantidad_basic_blocks , address_hija );

    /* Levanto la segunda tanda */
      for ( cont2 = cont1 + 1 ; cont2 < ranking_pesos.Len () ; cont2 ++ )
      {
      /* Levanto la siguiente conexion hija */
        address_hija = ( unsigned int ) ranking_pesos.Get ( cont2 );

      /* Obtengo el basic block */
        basic_block_hijo2 = get_basic_block_from_array ( funcion -> basic_blocks , funcion -> cantidad_basic_blocks , address_hija );

      /* Si el basic block 1 es mas pesado que el segundo */
        if ( basic_block_hijo1 -> peso > basic_block_hijo2 -> peso )
        {
        /* Me quedo con el segundo elemento */
          basic_block_hijo1 = basic_block_hijo2;

        /* Invierto los basic blocks de la lista */
          ranking_pesos.Swap ( cont1 , cont2 );
        }
      }
    }
  }

/* Recorro todas las conexiones ordenadas */
  for ( cont1 = 0 ; cont1 < ranking_pesos.Len () ; cont1 ++ )
  {
  /* Levanto la siguiente conexion hija ordenada */
    address_hija = ( unsigned int ) ranking_pesos.Get ( cont1 );

  /* Obtengo el basic block */
    basic_block_hijo1 = get_basic_block_from_array ( funcion -> basic_blocks , funcion -> cantidad_basic_blocks , address_hija );

  /* Si este basic block NO tiene ID */
    if ( basic_block_hijo1 -> id == -1 )
    {
    /* Avanzo por este camino */
      poner_ids_a_basic_blocks ( id_actual + 1 , funcion , basic_block_hijo1 );
    }
  }
}

/****************************************************************************/ 

char *generar_ecuacion_de_grafo_de_funcion ( Funcion *funcion )
{
  List ids;
  Basic_Block *basic_block_actual;
  Basic_Block *basic_block_hijo;
  unsigned int cantidad_ids = 0;
  unsigned int hijos, nietos;
  unsigned int longitud_ecuacion;
  unsigned int address_hija;
  unsigned int cont, cont2;
  char link [ 64 ];
  char *ecuacion;
  int id;

/* Creo el espacio para la ecuacion de la funcion */
  ecuacion = ( char * ) malloc ( 1 );

/* Inicializo la ecuacion */
  qstrncpy ( ecuacion , "" , 1 );

/* Inicializo el string que va a contener las relaciones */
  qstrncpy ( link , "" , 1 );

/* Calculo la cantidad de basic blocks que tienen ID */
  for ( cont = 0 ; cont < funcion -> cantidad_basic_blocks ; cont ++ )
  {
  /* Si el basic block tiene ID */
    if ( funcion -> basic_blocks [ cont ] -> id != -1 )
    {
    /* Incremento la cantidad de basic blocks para armar la ecuacion */
      cantidad_ids ++;
    }
  }

/* Recorro la cantidad de basic blocks involucrados en el grafo */
  for ( cont = 0 ; cont < cantidad_ids ; cont ++ )
  {
  /* Limpio la lista */
    ids.Clear ();

  /* Busco el basic block que tenga este ID */
    basic_block_actual = get_basic_block_by_id ( funcion , cont );

  /* Recorro todos los hijos del basic block */
    for ( cont2 = 0 ; cont2 < basic_block_actual -> basic_blocks_hijos -> Len () ; cont2 ++ )
    {
    /* Levanto la siguiente direccion */
      address_hija = ( unsigned int ) basic_block_actual -> basic_blocks_hijos -> Get ( cont2 );

    /* Levanto el basic block */
      basic_block_hijo = get_basic_block_from_array ( funcion -> basic_blocks , funcion -> cantidad_basic_blocks , address_hija );

    /* Agrego el ID a la lista */
      ids.Add ( ( void * ) basic_block_hijo -> id );
    }

  /* Ordeno los IDs */
    ids.Sort ();

  /* Recorro toda la lista ordenada por ID */
    for ( cont2 = 0 ; cont2 < ids.Len () ; cont2 ++ )
    {
    /* Levanto el siguiente ID */
      id = ( int ) ids.Get ( cont2 );

    /* Busco el basic block que tenga este ID */
      basic_block_hijo = get_basic_block_by_id ( funcion , id );

      if ( basic_block_hijo -> id == -1 )
      {
        my_msg ( "bb %x = ID -1\n" , basic_block_hijo -> addr_inicial );
      }

    /* Seteo la cantidad de hijos de los basic blocks */
      hijos = basic_block_actual -> funciones_hijas -> Len ();
      nietos = basic_block_hijo -> funciones_hijas -> Len ();

    /* Imprimo la conexion */
      qsnprintf ( link , 64 , "%i(%i)-%i(%i)," , basic_block_actual -> id , hijos , basic_block_hijo -> id , nietos );

    /* Calculo la longitud de la ecuacion */
      longitud_ecuacion = strlen ( ecuacion ) + strlen ( link ) + 1;

    /* Agrando la ecuacion */
      ecuacion = ( char * ) realloc ( ecuacion , longitud_ecuacion );

    /* Anexo el ultimo link */
      qstrncat ( ecuacion , link , longitud_ecuacion );
    }
  }

  return ( ecuacion );
}

/****************************************************************************/ 

Basic_Block *get_basic_block_by_id ( Funcion *funcion , int id )
{
  Basic_Block *basic_block;
  unsigned int cont;

/* Recorro toda la lista de basic blocks */
  for ( cont = 0 ; cont < funcion -> cantidad_basic_blocks ; cont ++ )
  {
  /* Levanto el siguiente basic block */
    basic_block = funcion -> basic_blocks [ cont ];

  /* Si el basic block tiene el ID que estoy buscando */
    if ( basic_block -> id == id )
    {
    /* Retorno el basic block buscado */
      break;
    }
  }

  return ( basic_block );
}

/****************************************************************************/ 

Basic_Block *get_basic_block_by_association_id ( Funcion *funcion , int id )
{
  Basic_Block *basic_block;
  unsigned int cont;

/* Recorro toda la lista de basic blocks */
  for ( cont = 0 ; cont < funcion -> cantidad_basic_blocks ; cont ++ )
  {
  /* Levanto el siguiente basic block */
    basic_block = funcion -> basic_blocks [ cont ];

  /* Si el basic block tiene el ID que estoy buscando */
    if ( basic_block -> association_id == id )
    {
    /* Retorno el basic block buscado */
      break;
    }
  }

  return ( basic_block );
}

/****************************************************************************/ 

void liberar_basic_blocks ( Funcion *funcion )
{
  Basic_Block *basic_block;
  unsigned int cont;

/* Recorro todos los basic blocks */
  for ( cont = 0 ; cont < funcion -> cantidad_basic_blocks ; cont ++ )
  {
  /* Levanto el siguiente basic block */
    basic_block = funcion -> basic_blocks [ cont ];

  /* Marco el basic block como LIBRE */
    basic_block -> visitado = FALSE;
  }
}

/****************************************************************************/

int guardar_analisis ( char *filename )
{
  Funcion *funcion;
  unsigned int referencia_hija;
  unsigned int cont;
  unsigned int cont2;
  unsigned int cont3;
  int ret = TRUE;
  FILE *f;

/* Creo el archivo donde voy a guardar el analisis */
  f = qfopen ( filename , "wb" );

/* Guardo la version del differ */
  qfwrite ( f , ( void * ) &turbodiff_version , sizeof ( version ) );

/* Recorro todas las funciones detectadas */
  for ( cont = 0 ; cont < funciones.Len () ; cont ++ )
  {
  /* Levanto la siguiente funcion */
    funcion = ( Funcion * ) funciones.Get ( cont );

  /* Guardo el analisis de la funcion */
    qfwrite ( f , funcion , sizeof ( Funcion ) );

  /* Guardo todos los basic blocks */
    for ( cont2 = 0 ; cont2 < funcion -> cantidad_basic_blocks ; cont2 ++ )
    {
    /* Guardo el siguiente basic block en el file */
      qfwrite ( f , funcion -> basic_blocks [ cont2 ] , sizeof ( Basic_Block ) );

    /* Guardo todas las conexiones con los basic blocks hijos */
      funcion -> basic_blocks [ cont2 ] -> basic_blocks_hijos -> Save ( f );

    /* Guardo todas las referencias de este basic block */
      for ( cont3 = 0 ; cont3 < funcion -> basic_blocks [ cont2 ] -> cantidad_referencias ; cont3 ++ )
      {
      /* Levanto la siguiente direccion */
        referencia_hija = ( unsigned int ) funcion -> basic_blocks [ cont2 ] -> funciones_hijas -> Get ( cont3 );

      /* Guardo la direccion */
        qfwrite ( f , &referencia_hija , sizeof ( unsigned int ) );
      }

    /* Guardo la lista PERSISTENTE de conexiones DEBILES ( vtables ) */
      funcion -> basic_blocks [ cont2 ] -> ptr_funciones_hijas -> Save ( f );
    }

  /* Guardo todas las referencias padre */
    qfwrite ( f , funcion -> basic_blocks_padres , funcion -> cantidad_referencias_padre * sizeof ( Basic_Block_Padre ) );

  /* Guardo todas las referencias a traves de vtables */
//    qfwrite ( f , funcion -> referencias_x_vtable , funcion -> cantidad_referencias_x_vtable * sizeof ( Referencia_Vtable ) );
    funcion -> referencias_padre_x_vtable -> Save ( f );
  }

/* Cierro el archivo */
  qfclose ( f );

  return ( ret );
}

/****************************************************************************/ 

int guardar_desensamblado ( char *file_dis )
{
  Funcion *funcion;
  unsigned int pos;
  int ret = TRUE;
  FILE *fdis;

/* Intento abrir el file */
  fdis = qfopen ( file_dis , "wb" );

/* Si no pude abrir el archivo */
  if ( fdis == NULL )
  {
  /* Retorno ERROR */
    return ( FALSE );
  }

/* Recorro todas las funciones */
  for ( pos = 0 ; pos < funciones.Len () ; pos ++ )
  {
  /* Levanto la siguiente funcion */
    funcion = ( Funcion * ) funciones.Get ( pos );

  /* Guardo el codigo desensamblado de la funcion */
    guardar_desensamblado_de_funcion ( fdis , funcion );
  }

/* Cierro el file */
  qfclose ( fdis );

  return ( ret );
}

/****************************************************************************/ 

int guardar_desensamblado_de_funcion ( FILE *fdis , Funcion *funcion )
{
  List *cadena_basic_blocks;
  String desensamblado;
  char instruccion [ 256 ];
  unsigned int addr_actual;
  unsigned int len_instruccion;
  unsigned int cont, cont2, cont3;
  Basic_Block *basic_block;
  int ret = TRUE;

/* Recorro todos los basic blocks de la funcion */
  for ( cont = 0 ; cont < funcion -> cantidad_basic_blocks ; cont ++ )
  {
  /* Levanto el siguiente basic block */
    basic_block = funcion -> basic_blocks [ cont ];

  /* Obtengo la posicion en el file donde esta el desensamblado del basic block */
    basic_block -> pos_file_disasm = qftell ( fdis );

  /* Obtengo el encadenamiento de basic blocks */
    cadena_basic_blocks = basic_block -> cadena_basic_blocks;

  /* Reinicializo el string donde van a ir a parar las instrucciones del basic block */
    desensamblado.Reset ();

  /* Recorro toda la cadena de basic blocks simples */
    for ( cont3 = 0 ; cont3 < cadena_basic_blocks -> Len () ; cont3 = cont3 + 2 )
    {
    /* Direccion inicial del basic block simple */
      addr_actual = ( unsigned int ) cadena_basic_blocks -> Get ( cont3 );

    /* Guardo las n instrucciones en el file */
      for ( cont2 = 0 ; cont2 < ( unsigned int ) cadena_basic_blocks -> Get ( cont3 + 1 ) ; cont2 ++ )
      {
      /* Averiguo la longitud en bytes de la instruccion */
        len_instruccion = get_item_size ( addr_actual );

      /* Levanto la siguiente instruccion */
        get_instruction ( addr_actual , instruccion , 256 );

      /* Anexo la siguiente instruccion */
        desensamblado.Append ( instruccion );

      /* Anexo un ENTER */
        desensamblado.Append ( "\n" );

      /* Avanzo a la siguiente instruccion */
        addr_actual = addr_actual + len_instruccion;
      }
    }

  /* Guardo el desensamblado del basic block en el file */
    desensamblado.Save ( fdis );
  }

  return ( ret );
}                                                

/****************************************************************************/ 

char *get_instruction ( unsigned int address , char *instruction , unsigned int buffer_len )
{
  unsigned int longitud;
  unsigned int pos1, pos2;
  char s [ 256 ];

/* Desensamblo la linea */
  generate_disasm_line ( address , s , 256 );

/* Longitud de la instruccion */
  longitud = strlen ( s );

/* Voy copiando el string limpito al destino */
  for ( pos1 = 0 , pos2 = 0 ; pos1 < longitud , ( pos2 + 1 ) < buffer_len ; pos1 ++ )
  {
  /* Si detecto una referencia en el programa */
    if ( ( s [ pos1 ] == 0x01 ) && ( s [ pos1 + 1 ] == 0x28 ) )
    {
    /* Avanzo 2 posiciones en el string */
      pos1 = pos1 + 2 + ( sizeof ( unsigned int ) * 2 );
    }

  /* Si no es ningun caracter especial */
    if ( ( s [ pos1 ] != 0x01 ) && ( s [ pos1 ] != 0x02 ) )
    {
    /* Si NO es una comilla */
      if ( s [ pos1 ] != '"' )
      {
      /* Copio el siguiente caracter */
        instruction [ pos2 ] = s [ pos1 ];
      }
    /* Si es una comilla */
      else
      {
      /* Reemplazo la comilla doble por una comilla simple */
        instruction [ pos2 ] = '\'';
      }

    /* Avanzo en el string destino */
      pos2 ++;
    }
    else
    {
    /* Salteo el proximo byte */
      pos1 ++;
    }
  }   

/* Cierro el string generado */
  instruction [ pos2 ] = '\x00';

/* Retorno el string armado */
  return ( instruction );
}

/****************************************************************************/ 

int comparar_files ( char *filename1 , char *filename2 , char *log_file , int usar_simbolos )
{
  Funcion *funcion;
  Funcion *funcion1;
  Funcion *funcion2;
  char error_message [ 256 ];
  char funcion1_name [ NAME_LEN ];
  char funcion2_name [ NAME_LEN ];
  unsigned int error_pos;
  unsigned int file1_version;
  unsigned int file2_version;
  unsigned int cont, cont1, cont2;
  unsigned int pos;
  unsigned int pasada = 0;
  int funciones_reconocidas;
  int matched_functions;
  int ret = TRUE;
  FILE *f_log_file;
  FILE *f1;
  FILE *f2;
  int err;

/* Abro el primer archivo */
  f1 = qfopen ( filename1 , "rb" );

/* Abro el segundo archivo */
  f2 = qfopen ( filename2 , "rb" );

/* Si no pude abrir alguno de los 2 archivos */
  if ( ( f1 == NULL ) || ( f2 == NULL ) )
  {
  /* Retorno ERROR */
    return ( FALSE );
  }

/* Leo la version de los files */
  qfread ( f1 , ( void * ) &file1_version , sizeof ( unsigned int ) );
  qfread ( f2 , ( void * ) &file2_version , sizeof ( unsigned int ) );

/* Si alguna de las versiones NO coincide con la actual */
  if ( ( file1_version != turbodiff_version ) || ( file2_version != turbodiff_version ) )
  {
  /* Mensaje al usuario */
    my_msg ( "ERROR: Different file versions, please take the analysis again\n" );

  /* Retorno ERROR */
    return ( FALSE );
  }

/* Abro el file para loguear el resultado */
  if ( ( f_log_file = qfopen ( log_file , "wt" ) ) == NULL )
  {
  /* Mensaje de ERROR */
    MessageBox ( NULL , "cannot open log file" , "ERROR" , MB_ICONERROR | MB_TOPMOST );

  /* Retorno ERROR */
    return ( FALSE );
  }

/* Levanto todas las funciones analizadas de file1 */
  my_msg ( "loading %s ...\n" , filename1 );
  levantar_funciones ( f1 , indice_funciones1 , funciones1 );

/* Hago una copia de la lista de funciones */
  for ( pos = 0 ; pos < funciones1.Len () ; pos ++ )
  {
  /* Levanto el siguiente elemento */
    funcion = ( Funcion * ) funciones1.Get ( pos );

  /* Duplico el elemento */
    funciones1_levantadas.Add ( funcion );
  }

/* Levanto todas las funciones analizadas de file2 */
  my_msg ( "loading %s ...\n" , filename2 );
  levantar_funciones ( f2 , indice_funciones2 , funciones2 );

/* Hago una copia de la lista de funciones */
  for ( pos = 0 ; pos < funciones2.Len () ; pos ++ )
  {
  /* Levanto el siguiente elemento */
    funcion = ( Funcion * ) funciones2.Get ( pos );

  /* Duplico el elemento */
    funciones2_levantadas.Add ( funcion );
  }

/* Cierro los archivos */
  qfclose ( f1 );
  qfclose ( f2 );

/* Mensaje de funciones cargadas para el usuario */
  my_msg ( "loaded functions for file1: %i\n" , funciones1_levantadas.Len () );
  my_msg ( "loaded functions for file2: %i\n" , funciones2_levantadas.Len () );

/* Arranco a analizar todas las funciones */
  my_msg ( "comparing functions ...\n" );

////////////////////////////////////////

/* Si puedo usar los simbolos */
  if ( usar_simbolos == TRUE )
  {
  /* Recorro todas las funciones de programa1 */
    for ( cont = 0 ; cont < funciones1_levantadas.Len () ; cont ++ )
    {
    /* Levanto la siguiente funcion */
      funcion1 = ( Funcion * ) funciones1_levantadas.Get ( cont );

    /* Si la funcion tiene nombre */
      if ( strncmp ( funcion1 -> name , "sub_" , 4 ) != 0 )
      {
      /* Busco en programa2 esta misma funcion */
        for ( cont2 = 0 ; cont2 < funciones2_levantadas.Len () ; cont2 ++ )
        {
        /* Levanto la siguiente funcion */
          funcion2 = ( Funcion * ) funciones2_levantadas.Get ( cont2 );

        /* Si esta funcion es la que estoy buscando */
          if ( tienen_el_mismo_nombre ( funcion1 , funcion2 ) == TRUE )
          {
          /* Si las funciones son identicas */
            if ( son_funciones_iguales ( funcion1 , funcion2 ) == TRUE )
            {
            /* Relaciono las funciones */
              asociar_funciones ( TRUE , funcion1 , funcion2 , funciones1_reconocidas , funciones2_reconocidas , funciones1_levantadas , funciones2_levantadas );
            }
          /* Si son funciones patcheadas */
            else
            {
            /* Relaciono las funciones */
              asociar_funciones ( FALSE , funcion1 , funcion2 , funciones1_cambiadas , funciones2_cambiadas , funciones1_levantadas , funciones2_levantadas );
            }

          /* Compenso el puntero en la lista de programa1 */
            cont --;

          /* Corto la busqueda en programa2 */
            break;
          }
        }
      }
    }
  }

////////////////////////////////////////

/* Recorro todas las funciones buscando las que son IDENTICAS */
  while ( funciones1_levantadas.Len () > 0 )
  {
  /* Marco el flag de funciones matcheadas */
    matched_functions = FALSE;

  /* Levanto la proxima funcion de 1 */
    funcion1 = ( Funcion * ) funciones1_levantadas.Get ( 0 );

  /* Si la funcion tiene mas de 1 basic block o tiene un checksum confiable */
    if ( ( funcion1 -> cantidad_basic_blocks > 1 ) || ( funcion1 -> checksum & 0xfff ) )
    {
    /* Levanto todas las funciones2 */
      for ( pos = 0 ; pos < funciones2_levantadas.Len () ; pos ++ )
      {
      /* Levanto la proxima funcion de 2 */
        funcion2 = ( Funcion * ) funciones2_levantadas.Get ( pos );

      /* Si las funciones son iguales */
        if ( son_funciones_iguales ( funcion1 , funcion2 ) == TRUE )
        {
        /* Relaciono las 2 funciones */
          asociar_funciones ( TRUE , funcion1 , funcion2 , funciones1_reconocidas , funciones2_reconocidas , funciones1_levantadas , funciones2_levantadas );
    
        /* Marco el flag de funciones matcheadas */
          matched_functions = TRUE;

        /* Paso a la siguiente funcion */
          break;
        }
      }
    }

  /* Si no pude matchear esta funcion */
    if ( matched_functions == FALSE )
    {
    /* Saco la funcion1 y la paso a la lista de intermedias */
      funciones1_intermedias.Add ( funcion1 );
      funciones1_levantadas.DeleteElement ( funcion1 );
    }
  }

////////////////////////////////////////

/* Recorro todas las funciones buscando las que son CUASI-IDENTICAS */
  for ( cont = 0 ; cont < funciones1_intermedias.Len () ; cont ++ )
  {
  /* Levanto la proxima funcion de 1 */
    funcion1 = ( Funcion * ) funciones1_intermedias.Get ( cont );

  /* Levanto todas las funciones2 */
    for ( pos = 0 ; pos < funciones2_levantadas.Len () ; pos ++ )
    {
    /* Levanto la proxima funcion de 2 */
      funcion2 = ( Funcion * ) funciones2_levantadas.Get ( pos );

    /* Si son funciones cuasi-identicas */
      if ( son_funciones_cuasi_identicas ( funcion1 , funcion2 ) == TRUE )
      {
      /* Relaciono las 2 funciones */
        asociar_funciones ( FALSE , funcion1 , funcion2 , funciones1_cambiadas , funciones2_cambiadas , funciones1_intermedias , funciones2_levantadas );

      /* Compenso la extraccion de la funcion */
        cont --;

      /* Sigo buscando */
        break;
      }
    }
  }

////////////////////////////////////////

/* Recorro todas las funciones buscando las que cambiaron */
/* y las reconozco desde las funciones identicas */
  while ( funciones1_intermedias.Len () > 0 )
  {
  /* Marco el flag de funciones matcheadas */
    matched_functions = FALSE;

  /* Levanto la proxima funcion de 1 */
    funcion1 = ( Funcion * ) funciones1_intermedias.Get ( 0 );

    // nicolas 
//    my_msg ( "?son patcheadas %x %x\n" , funcion1 -> address , funcion2 -> address );

  /* Si es una funcion que esta patcheada */
    if ( es_funcion_patcheada ( funcion1 , funciones2 , &funcion2 ) == TRUE )
    {
    /* Relaciono las 2 funciones */
      asociar_funciones ( FALSE , funcion1 , funcion2 , funciones1_cambiadas , funciones2_cambiadas , funciones1_intermedias , funciones2_levantadas );

    /* Marco el flag de funciones matcheadas */
      matched_functions = TRUE;
    }

  /* Si no pude matchear esta funcion */
    if ( matched_functions == FALSE )
    {
    /* Saco la funcion1 y la paso a la lista de irreconocidas */
      funciones1_irreconocidas.Add ( funcion1 );
      funciones1_intermedias.DeleteElement ( funcion1 );
    }
  }

////////////////////////////////////////
////////////////////////////////////////

/* Recorro toda la lista de funciones intermedias */
  for ( pos = 0 ; pos < funciones1_irreconocidas.Len () ; pos ++ )
  {
  /* Levanto la proxima funcion de 1 */
    funcion1 = ( Funcion * ) funciones1_irreconocidas.Get ( pos );

  /* Analizar esta funcion SI TIENE UN PADRE en la lista de cambiadas */
    // nicolas

  /* Si la funcion fue reconocida */
    if ( es_funcion_patcheada ( funcion1 , funciones2 , &funcion2 ) == TRUE )
    {
    /* Relaciono las 2 funciones */
      asociar_funciones ( FALSE , funcion1 , funcion2 , funciones1_cambiadas , funciones2_cambiadas , funciones1_irreconocidas , funciones2_levantadas );

    /* Decremento la posicion en la lista para compensar la extraccion del elemento */
      pos --;
    }
  }

////////////////////////////////////////

/* Reconozco las funciones que tienen la misma geometria */
//  reconocer_funciones_con_misma_geometria ( funciones1_cambiadas , funciones2_cambiadas , funciones1_irreconocidas , funciones2_levantadas );

////////////////////////////////////////

// nicolas
//  goto salto;

/* Recorro todas las funciones que me quedaron sueltas */
/* y las reconozco desde las funciones cambiadas */
  do
  {
  /* Cuento la cantidad de pasadas */
    pasada ++;

  /* Seteo el contador de funciones reconocidas analizando las funciones patcheadas */
    funciones_reconocidas = 0;

  /* Recorro toda la lista de funciones intermedias */
    for ( pos = 0 ; pos < funciones1_irreconocidas.Len () ; pos ++ )
    {
    /* Levanto la proxima funcion de 1 */
      funcion1 = ( Funcion * ) funciones1_irreconocidas.Get ( pos );

    /* Analizar esta funcion SI TIENE UN PADRE en la lista de cambiadas */
      // nicolas

    /* Si la funcion fue reconocida */
      if ( es_funcion_patcheada ( funcion1 , funciones2 , &funcion2 ) == TRUE )
      {
      /* Relaciono las 2 funciones */
        asociar_funciones ( FALSE , funcion1 , funcion2 , funciones1_cambiadas , funciones2_cambiadas , funciones1_irreconocidas , funciones2_levantadas );

      /* Incremento la cantidad de funciones reconocidas */
        funciones_reconocidas ++;

      /* Decremento la posicion en la lista para compensar la extraccion del elemento */
        pos --;
      }
    }

//  salto:;

////////////////////////////////////////

//  goto salto2;

///* Recorro todas las funciones que me quedaron sueltas */
///* y las reconozco desde las funciones hijas */
//  /* Recorro todas las funciones huerfanas que no fueron reconocidas como identicas */
//    for ( pos = 0 ; pos < funciones1_irreconocidas.Len () ; pos ++ )
//    {
//    /* Levanto la siguiente funcion */
//      funcion1 = ( Funcion * ) funciones1_irreconocidas.Get ( pos );
//
//    /* Si reconozco la funcion a traves de los hijos */
//      if ( get_funcion_equivalente_x_hijos ( funcion1 , funciones1 , funciones2 , &funcion2 ) == TRUE )
//      {
////        my_msg ( "reconocida %x\n" , funcion1 -> address );
//
//      /* Relaciono las 2 funciones */
//        asociar_funciones ( FALSE , funcion1 , funcion2 , funciones1_cambiadas , funciones2_cambiadas , funciones1_irreconocidas , funciones2_levantadas );
//
//      /* Incremento la cantidad de funciones reconocidas */
//        funciones_reconocidas ++;
//
//      /* Decremento la posicion en la lista para compensar la extraccion del elemento */
//        pos --;
//      }
//    }

//  salto2:;

////////////////////////////////////////

  /* Mensaje al usuario */
    if ( funciones_reconocidas > 0 )
    {
//      my_msg ( "pasada %i: funciones reconocidas = %i\n" , pasada , funciones_reconocidas );
    }
  }
  while ( funciones_reconocidas > 0 );

////////////////////////////////////////

/* Reconozco todas las funciones a traves de vtables padres */
  reconocer_funciones_x_vtables ( funciones1 , funciones2 , funciones1_irreconocidas , funciones2_levantadas , funciones1_cambiadas , funciones2_cambiadas );

////////////////////////////////////////

/* Recorro todas las funciones que me quedaron sueltas en 2 */
  while ( funciones2_levantadas.Len () > 0 )
  {
  /* Levanto la proxima funcion de 2 */
    funcion2 = ( Funcion * ) funciones2_levantadas.Get ( 0 );

  /* Saco la funcion1 y la paso a la lista de irreconocidas */
    funciones2_irreconocidas.Add ( funcion2 );
    funciones2_levantadas.DeleteElement ( funcion2 );
  }

////////////////////////////////////////

/* Recorro todas las funciones que cambiaron */
/* e identifico las funciones IDENTICAS de un 1 basic block */
  for ( cont = 0 ; cont < funciones1_cambiadas.Len () ; cont ++ )
  {
  /* Levanto el siguiente par asociado */
    funcion1 = ( Funcion * ) funciones1_cambiadas.Get ( cont );
    funcion2 = ( Funcion * ) funciones2_cambiadas.Get ( cont );

  /* Si estan formadas por un solo basic block */
    if ( funcion1 -> cantidad_basic_blocks == 1 )
    {
    /* Si las funciones son IDENTICAS */
      if ( son_funciones_iguales ( funcion1 , funcion2 ) == TRUE )
      {
      /* Asumo que son identicas */
        asociar_funciones ( TRUE , funcion1 , funcion2 , funciones1_reconocidas , funciones2_reconocidas , funciones1_cambiadas , funciones2_cambiadas );

      /* Compenso la extraccion */
        cont --;
      }
    }
  }

////////////////////////////////////////

/* Discrimino los cambios importantes de los triviales */
/* en las funciones cambiadas */
  clasificar_funciones_cambiadas ( funciones1_cambiadas , funciones2_cambiadas , funciones1_matcheadas , funciones2_matcheadas );

////////////////////////////////////////

/* Separador */
  my_msg ( "-------------------------------------------------------------\n" );
  qfprintf ( f_log_file , "-------------------------------------------------------------\n" );
  my_msg ( "-------------------------------------------------------------\n" );
  qfprintf ( f_log_file , "-------------------------------------------------------------\n" );

/* Imprimo el reporte */
  my_msg ( "identical functions: %i\n" , funciones1_reconocidas.Len () );
  qfprintf ( f_log_file , "identical functions: %i\n" , funciones1_reconocidas.Len () );

/* Imprimo las funciones que son identicas */
  for ( pos = 0 ; pos < funciones1_reconocidas.Len () ; pos ++ )
  {
  /* Levanto las funciones cambiadas de los 2 archivos */
    funcion1 = ( Funcion * ) funciones1_reconocidas.Get ( pos );
    funcion2 = ( Funcion * ) funciones2_reconocidas.Get ( pos );

  /* Formateo el nombre de las funciones para poderlos imprimir */
    get_formated_name ( funcion1 , funcion1_name , NAME_LEN , TRUE );
    get_formated_name ( funcion2 , funcion2_name , NAME_LEN , TRUE );

  /* Imprimo los pares */
    qfprintf ( f_log_file , "%.8x %.48s - %.8x %.48s\n" , funcion1 -> address , funcion1_name , funcion2 -> address , funcion2_name );
  }

////////////////////

/* Separador */
  my_msg ( "-------------------------------------------------------------\n" );
  qfprintf ( f_log_file , "-------------------------------------------------------------\n" );

/* Imprimo el reporte */
  my_msg ( "matched functions: %i\n" , funciones1_matcheadas.Len () + funciones1_geometricamente_identicas.Len () );
  qfprintf ( f_log_file , "matched functions: %i\n" , funciones1_matcheadas.Len () + funciones1_geometricamente_identicas.Len () );

/* Imprimo las funciones que cambiaron */
  for ( pos = 0 ; pos < funciones1_matcheadas.Len () ; pos ++ )
  {
  /* Levanto las funciones cambiadas de los 2 archivos */
    funcion1 = ( Funcion * ) funciones1_matcheadas.Get ( pos );
    funcion2 = ( Funcion * ) funciones2_matcheadas.Get ( pos );

  /* Formateo el nombre de las funciones */
    get_formated_name ( funcion1 , funcion1_name , NAME_LEN , TRUE );
    get_formated_name ( funcion2 , funcion2_name , NAME_LEN , TRUE );

  /* Imprimo los pares */
    qfprintf ( f_log_file , "[.] %.8x %.48s - %.8x %.48s\n" , funcion1 -> address , funcion1_name , funcion2 -> address , funcion2_name );
  }

/* Imprimo las funciones que cambiaron */
  for ( pos = 0 ; pos < funciones1_geometricamente_identicas.Len () ; pos ++ )
  {
  /* Levanto las funciones cambiadas de los 2 archivos */
    funcion1 = ( Funcion * ) funciones1_geometricamente_identicas.Get ( pos );
    funcion2 = ( Funcion * ) funciones2_geometricamente_identicas.Get ( pos );

  /* Formateo el nombre de las funciones */
    get_formated_name ( funcion1 , funcion1_name , NAME_LEN , TRUE );
    get_formated_name ( funcion2 , funcion2_name , NAME_LEN , TRUE );

  /* Imprimo los pares */
    qfprintf ( f_log_file , "[*] %.8x %.48s - %.8x %.48s\n" , funcion1 -> address , funcion1_name , funcion2 -> address , funcion2_name );
  }

////////////////////

/* Separador */
  my_msg ( "-------------------------------------------------------------\n" );
  qfprintf ( f_log_file , "-------------------------------------------------------------\n" );

  my_msg ( "unmatched functions1: %i\n" , funciones1_irreconocidas.Len () );
  qfprintf ( f_log_file , "unmatched functions1: %i\n" , funciones1_irreconocidas.Len () );

/* Imprimo las funciones que no pude reconocer para file1 */
  for ( pos = 0 ; pos < funciones1_irreconocidas.Len () ; pos ++ )
  {
  /* Levanto las funciones cambiadas de los 2 archivos */
    funcion1 = ( Funcion * ) funciones1_irreconocidas.Get ( pos );

  /* Formateo el nombre de las funciones */
    get_formated_name ( funcion1 , funcion1_name , NAME_LEN , TRUE );

  /* Imprimo los pares */
    qfprintf ( f_log_file , "%.8x %s\n" , funcion1 -> address , funcion1_name );
  }

////////////////////

/* Separador */
  my_msg ( "-------------------------------------------------------------\n" );
  qfprintf ( f_log_file , "-------------------------------------------------------------\n" );

  my_msg ( "unmatched functions2: %i\n" , funciones2_irreconocidas.Len () );
  qfprintf ( f_log_file , "unmatched functions2: %i\n" , funciones2_irreconocidas.Len () );

/* Imprimo las funciones que no pude reconocer para file2 */
  for ( pos = 0 ; pos < funciones2_irreconocidas.Len () ; pos ++ )
  {
  /* Levanto las funciones cambiadas de los 2 archivos */
    funcion2 = ( Funcion * ) funciones2_irreconocidas.Get ( pos );

  /* Formateo el nombre de las funciones */
    get_formated_name ( funcion2 , funcion2_name , NAME_LEN , TRUE );

  /* Imprimo los pares */
    qfprintf ( f_log_file , "%.8x %s\n" , funcion2 -> address , funcion2_name );
  }

////////////////////

/* Separador */
  my_msg ( "-------------------------------------------------------------\n" );
  qfprintf ( f_log_file , "-------------------------------------------------------------\n" );

/* Imprimo todas las funciones que cambiaron */
  my_msg ( "changed functions: %i\n" , funciones1_cambiadas.Len () );
  qfprintf ( f_log_file , "changed functions: %i\n" , funciones1_cambiadas.Len () );

/* Recorro todas las funciones que cambiaron */
  for ( pos = 0 ; pos < funciones1_cambiadas.Len () ; pos ++ )
  {
  /* Levanto las funciones cambiadas de los 2 archivos */
    funcion1 = ( Funcion * ) funciones1_cambiadas.Get ( pos );
    funcion2 = ( Funcion * ) funciones2_cambiadas.Get ( pos );

  /* Formateo el nombre de las funciones */
    get_formated_name ( funcion1 , funcion1_name , NAME_LEN , TRUE );
    get_formated_name ( funcion2 , funcion2_name , NAME_LEN , TRUE );

  /* Imprimo los pares */
    qfprintf ( f_log_file , "[%c] %.8x %.48s - [%c] %.8x %.48s\n" , '.' , funcion1 -> address , funcion1_name , '.' , funcion2 -> address , funcion2_name );
  }

////////////////////

/* Separador */
  my_msg ( "-------------------------------------------------------------\n" );
  qfprintf ( f_log_file , "-------------------------------------------------------------\n" );
  my_msg ( "-------------------------------------------------------------\n" );
  qfprintf ( f_log_file , "-------------------------------------------------------------\n" );

/* Aviso al usuario */
  my_msg ( "logued output in %s\n" , log_file );

/* Cierro el archivo de logueo */
  qfclose ( f_log_file );

  return ( ret );
}

/****************************************************************************/ 

void get_formated_name ( Funcion *funcion , char *name , unsigned int len , int fill )
{
/* Si la funcion tiene un nombre demangleado */
  if ( strlen ( funcion -> demangled_name ) > 0 )
  {
  /* Escribo el nombre de la funcion en el buffer */
    qstrncpy ( name , funcion -> demangled_name , len );
  }
/* Si la funcion NO tiene un nombre que se puede demanglear */
  else
  {
  /* Escribo el nombre de la funcion en el buffer */
    qstrncpy ( name , funcion -> name , len );
  }

/* Si tengo que completar el nombre de la funcion con espacios */
  if ( fill == TRUE )
  {
  /* Relleno lo que falta con espacios en blanco */
    memset ( &name [ strlen ( name ) ] , ' ' , len - strlen ( name ) - 1 );

  /* Pongo el fin de string */
    name [ len - 1 ] = '\x00';
  }
}

/****************************************************************************/ 

int levantar_funciones ( FILE *f , List &indice_funciones , List &funciones )
{
  Funcion *funcion_padre;
  Funcion *funcion;
  unsigned int cont, cont2;
  unsigned int pos, pos2;
  unsigned int referencia_hija;
  int err;
  int ret = TRUE;

/* Mientras haya funciones por leer */
  while ( 1 )
  {
  /* Alloco espacio para la funcion a cargar */
    funcion = ( Funcion * ) malloc ( sizeof ( Funcion ) );

  /* Levanto la funcion del archivo */
    err = qfread ( f , funcion , sizeof ( Funcion ) );

  /* Si llegue al final del archivo */
    if ( err == 0 )
    {
    /* Corto la busqueda */
      break;
    }

  /* Alloco espacio y guardo los basic blocks */
    funcion -> basic_blocks = ( Basic_Block ** ) malloc ( sizeof ( Basic_Block * ) * funcion -> cantidad_basic_blocks );

  /* Levanto basic block a basic block */
    for ( cont = 0 ; cont < funcion -> cantidad_basic_blocks ; cont ++ )
    {
    /* Alloco espacio para un basic block mas */
      funcion -> basic_blocks [ cont ] = ( Basic_Block * ) malloc ( sizeof ( Basic_Block ) );

    /* Levanto el basic block a la memoria */
      qfread ( f , funcion -> basic_blocks [ cont ] , sizeof ( Basic_Block ) );

    /* Creo la lista PERSISTENTE que contiene los basic blocks hijos */
      funcion -> basic_blocks [ cont ] -> basic_blocks_hijos = new ( List );

    /* Levanto la lista */
      funcion -> basic_blocks [ cont ] -> basic_blocks_hijos -> Load ( f );

    /* Inicializo la lista de llamados a funciones */
      funcion -> basic_blocks [ cont ] -> funciones_hijas = new ( List );

    /* Levanto los llamados a funciones del basic block */
      for ( cont2 = 0 ; cont2 < funcion -> basic_blocks [ cont ] -> cantidad_referencias ; cont2 ++ )
      {
      /* Levanto el siguiente llamado */
        qfread ( f , &referencia_hija , sizeof ( unsigned int ) ); 

      /* Agrego el llamado a la lista */
        funcion -> basic_blocks [ cont ] -> funciones_hijas -> Add ( ( void * ) referencia_hija );
      }

    /* Creo la lista PERSISTENTE para contener los punteros a funciones */
      funcion -> basic_blocks [ cont ] -> ptr_funciones_hijas = new ( List );

    /* Levanto los punteros a funciones ( vtables ) del basic block */
      funcion -> basic_blocks [ cont ] -> ptr_funciones_hijas -> Load ( f );
    }

  /* Genero la ecuacion que representa al grafo de la funcion */
    funcion -> graph_ecuation = generar_ecuacion_de_grafo_de_funcion ( funcion );

  /* Levanto todas las referencias padre */
    funcion -> basic_blocks_padres = ( Basic_Block_Padre * ) malloc ( funcion -> cantidad_referencias_padre * sizeof ( Basic_Block_Padre ) );
    qfread ( f , funcion -> basic_blocks_padres , funcion -> cantidad_referencias_padre * sizeof ( Basic_Block_Padre ) );

  /* Levanto todas las referencias a traves de vtables */
//    funcion -> referencias_x_vtable = ( Referencia_Vtable * ) malloc ( sizeof ( Referencia_Vtable ) * funcion -> cantidad_referencias_x_vtable );   
//    qfread ( f , funcion -> referencias_x_vtable , sizeof ( Referencia_Vtable ) * funcion -> cantidad_referencias_x_vtable );
    funcion -> referencias_padre_x_vtable = new ( List );
    funcion -> referencias_padre_x_vtable -> Load ( f );

  /* Agrego la direccion de la funcion a la lista */
    indice_funciones.Add ( ( void * ) funcion -> address );

  /* Agrego la funcion a la lista */
    funciones.Add ( funcion );
  }

/* Resuelvo todas las conexiones entre los basic blocks padres y sus funciones */
/* Recorro toda la lista de funciones */
  for ( pos = 0 ; pos < funciones.Len () ; pos ++ )
  {
  /* Levanto la siguiente funcion */
    funcion = ( Funcion * ) funciones.Get ( pos );

  /* Recorro todos los basic blocks padres */
    for ( pos2 = 0 ; pos2 < funcion -> cantidad_referencias_padre ; pos2 ++ )
    {
    /* Busco la funcion padre */
      funcion_padre = get_estructura_funcion2 ( indice_funciones , funciones , funcion -> basic_blocks_padres [ pos2 ].direccion_funcion );

    /* Mensaje para chequear ERRORES */  
      if ( funcion_padre == NULL )
      {
        my_msg ( "Warning: parent function %x doesn't exist\n" , funcion -> basic_blocks_padres [ pos2 ].direccion_funcion );
      }

    /* Linkeo el basic block padre con la funcion padre */
      funcion -> basic_blocks_padres [ pos2 ].funcion = funcion_padre;
    }
  }

  return ( ret );
}

/****************************************************************************/

int asociar_funciones ( int identica , Funcion *funcion1 , Funcion *funcion2 , List &reconocidas1 , List &reconocidas2 , List &funciones1 , List &funciones2 )
{
  Referencia_Vtable *vtable1_padre;
  Referencia_Vtable *vtable2_padre;
  unsigned int cont1, cont2;
  int ret = TRUE;

/* Si la funcion es identica */
  if ( identica == TRUE )
  {
  /* Seteo las funciones como identicas */
    funcion1 -> identica = TRUE;
    funcion2 -> identica = TRUE;
  }
/* Si la funcion esta patcheada */
  else
  {
  /* Seteo las funciones como patcheadas */
    funcion1 -> patcheada = TRUE;
    funcion2 -> patcheada = TRUE;
  }

/* Relaciono las funciones */
  funcion1 -> address_equivalente = funcion2 -> address;
  funcion2 -> address_equivalente = funcion1 -> address;

/* Agrego las funciones en la listas */
  reconocidas1.Add ( funcion1 );
  reconocidas2.Add ( funcion2 );

/* Saco las funciones de las otras listas */
  funciones1.DeleteElement ( funcion1 );
  funciones2.DeleteElement ( funcion2 );

  return ( ret );
}

/****************************************************************************/

int tienen_el_mismo_nombre ( Funcion *funcion1 , Funcion *funcion2 )
{
  int ret = FALSE;

/* Si las 2 funciones estan demangleadas */
  if ( ( strlen ( funcion1 -> demangled_name ) > 0 ) && ( strlen ( funcion2 -> demangled_name ) > 0 ) )
  {
  /* Comparo los nombres demangleados */
    if ( strncmp ( funcion1 -> demangled_name , funcion2 -> demangled_name , NAME_LEN ) == 0 )
    {
    /* Retorno OK */
      ret = TRUE;
    }
  }
/* Si las 2 funciones NO estan demangleadas, comparo el nombre sin demanglear */
  else if ( strncmp ( funcion1 -> name , funcion2 -> name , NAME_LEN ) == 0 )
  {
  /* Retorno OK */
    ret = TRUE;
  }

  return ( ret );
}

/****************************************************************************/

int reconocer_funciones_con_misma_geometria ( List &funciones1_reconocidas , List &funciones2_reconocidas , List &funciones1 , List &funciones2 )
{
  Funcion *funcion1;
  Funcion *funcion2;
  unsigned int cont, cont2;
  int ret = TRUE;

/* Recorro todas las funciones de programa1 */
  for ( cont = 0 ; cont < funciones1.Len () ; cont ++ )
  {
  /* Levanto la siguiente funcion */
    funcion1 = ( Funcion * ) funciones1.Get ( cont );

  /* Si la funcion no es confiable para asociarla con otra por su geometria */
    if ( funcion1 -> cantidad_basic_blocks == 1 )
    {
    /* Sigo con otra funcion */
      continue;
    }

  /* Recorro todas las funciones de programa2 */
    for ( cont2 = 0 ; cont2 < funciones2.Len () ; cont2 ++ )
    {
    /* Levanto la siguiente funcion */
      funcion2 = ( Funcion * ) funciones2.Get ( cont2 );

    /* Si las 2 funciones tienen la misma geometria */
      if ( strcmp ( funcion1 -> graph_ecuation , funcion2 -> graph_ecuation ) == 0 )
      {
//        my_msg ( "pareja formada: %x - %x\n" , funcion1 -> address , funcion2 -> address );

      /* Relaciono las 2 funciones */
        asociar_funciones ( FALSE , funcion1 , funcion2 , funciones1_reconocidas , funciones2_reconocidas , funciones1 , funciones2 );

      /* Decremento la posicion en la lista para compensar la extraccion del elemento */
        cont --;

      /* Corto la busqueda */
        break;
      }
    }
  }

  return ( ret );
}

/****************************************************************************/

unsigned int reconocer_funciones_x_vtables ( List &funciones1 , List &funciones2 , List &funciones1_irreconocidas , List &funciones2_irreconocidas , List &funciones1_cambiadas , List &funciones2_cambiadas )
{
  Funcion *funcion1;
  Funcion *funcion2;
  unsigned int cont1;
  unsigned int cont2;
  unsigned int funciones_reconocidas = 0;

/* Recorro todas las funciones irreconocidas */
  for ( cont1 = 0 ; cont1 < funciones1_irreconocidas.Len () ; cont1 ++ )
  {
  /* Levanto la siguiente funcion en programa1 */
    funcion1 = ( Funcion * ) funciones1_irreconocidas.Get ( cont1 );

  /* Si la funcion NO tiene referencias padre x vtable */
    if ( funcion1 -> referencias_padre_x_vtable -> Len () == 0 )
    {
    /* Sigo buscando */
      continue;
    }

  /* Recorro todas las funciones irreconocidas en programa2 */
    for ( cont2 = 0 ; cont2 < funciones2_irreconocidas.Len () ; cont2 ++ )
    {
    /* Levanto la siguiente funcion */
      funcion2 = ( Funcion * ) funciones2_irreconocidas.Get ( cont2 );

    /* Si la funcion NO tiene referencias padre x vtable */
      if ( funcion2 -> referencias_padre_x_vtable -> Len () == 0 )
      {
      /* Sigo buscando */
        continue;
      }

    /* Si son funciones equivalentes */
      if ( son_funciones_equivalentes_x_vtables ( funciones1 , funciones2 , funcion1 , funcion2 ) == TRUE )
      {
//        my_msg ( "igual_x_vtable: %x - %x\n" , funcion1 -> address , funcion2 -> address );

      /* Asocio las funciones */
        asociar_funciones ( FALSE , funcion1 , funcion2 , funciones1_cambiadas , funciones2_cambiadas , funciones1_irreconocidas , funciones2_irreconocidas );

      /* Compenso la extraccion de la lista */
        cont1 --;

      /* Aumento la cantidad de funciones reconocidas */
        funciones_reconocidas ++;

      /* Continuo en la proxima funcion */
        break;
      }
    }
  }

  return ( funciones_reconocidas );
}

/****************************************************************************/

int son_funciones_equivalentes_x_vtables ( List &funciones1 , List &funciones2 , Funcion *funcion1 , Funcion *funcion2 )
{
  Funcion *funcion1_padre;
  Funcion *funcion2_padre;
  Basic_Block *basic_block1_padre;
  Basic_Block *basic_block2_padre;
  unsigned int address_funcion_referenciada;
  unsigned int address_padre;
  unsigned int cont, cont1, cont2;
  unsigned int pos;
  int ret = FALSE;

/* Recorro todas las referencias padre x vtables */
  for ( cont = 0 ; cont < funcion1 -> referencias_padre_x_vtable -> Len () ; cont ++ )
  {
  /* Levanto la siguiente direccion */
    address_padre = ( unsigned int ) funcion1 -> referencias_padre_x_vtable -> Get ( cont );

  /* Obtengo la funcion padre */
    funcion1_padre = get_estructura_funcion ( funciones1 , address_padre );

  /* Si la funcion padre se asocio con alguna */
    if ( funcion1_padre -> identica == TRUE || funcion1_padre -> patcheada == TRUE )
    {
    /* Obtengo la pareja de funcion1 padre */
      funcion2_padre = get_estructura_funcion ( funciones2 , funcion1_padre -> address_equivalente );

    /* Recorro todos los basic blocks de funcion1 padre */
      for ( cont1 = 0 ; cont1 < funcion1_padre -> cantidad_basic_blocks ; cont1 ++ )
      {
      /* Levanto el siguiente basic block */
        basic_block1_padre = funcion1_padre -> basic_blocks [ cont1 ];

      /* Si el basic block tiene asociada una VTABLE */
        if ( basic_block1_padre -> ptr_funciones_hijas -> Len () > 0 )
        {
        /* Si la funcion NO esta en esta VTABLE */
          if ( basic_block1_padre -> ptr_funciones_hijas -> Find ( ( void * ) funcion1 -> address ) != TRUE )
          {
          /* Sigo buscando */
            continue;
          }
          else
          {
          /* Obtengo la posicion en la VTABLE de la funcion */
            basic_block1_padre -> ptr_funciones_hijas -> GetPos ( ( void * ) funcion1 -> address , &pos );
          }

        /* Recorro todos los basic blocks de funcion2 padre */
          for ( cont2 = 0 ; cont2 < funcion2_padre -> cantidad_basic_blocks ; cont2 ++ )
          {
          /* Levanto el siguiente basic block */
            basic_block2_padre = funcion2_padre -> basic_blocks [ cont2 ];

          /* Si el basic block tiene asociada una VTABLE */
            if ( basic_block2_padre -> ptr_funciones_hijas -> Len () > 0 )
            {
            /* Si las vtables miden lo mismo */
              if ( basic_block1_padre -> ptr_funciones_hijas -> Len () == basic_block2_padre -> ptr_funciones_hijas -> Len () )
              {
              /* Obtengo la direccion de la funcion referenciada por VTABLE2 en esa posicion */
                address_funcion_referenciada = ( unsigned int ) basic_block2_padre -> ptr_funciones_hijas -> Get ( pos );

              /* Si la funcion equivalente en la VTABLE2 es la que estoy buscando */
                if ( funcion2 -> address == address_funcion_referenciada )
                {
//                  my_msg ( "EQU --> bb1: %x, pos = %x\n" , basic_block1_padre -> addr_inicial , pos );
                  
                /* Retorno OK */
                  return ( TRUE );
                }
              }
            }
          }
        }
      }
    }
  }

  return ( ret );
}

/****************************************************************************/

int son_funciones_iguales ( Funcion *funcion1 , Funcion *funcion2 )
{
  int ret = FALSE;

/* Si las funciones tienen la misma longitud */
  if ( funcion1 -> longitud == funcion2 -> longitud )
  {
  /* Si tienen el mismo checksum */
    if ( funcion1 -> checksum == funcion2 -> checksum )
    {
    /* Si tienen la misma geometria */
      if ( strcmp ( funcion1 -> graph_ecuation , funcion2 -> graph_ecuation ) == 0 )
      {
      /* Asumo que las funciones son iguales */
        ret = TRUE;
      }
    }
  }

  return ( ret );
}

/****************************************************************************/

int son_funciones_cuasi_identicas ( Funcion *funcion1 , Funcion *funcion2 )
{
  int ret = FALSE;

/* Si las funciones tienen mas de un basic block */
  if ( funcion1 -> cantidad_basic_blocks > 1 )
  {
  /* Si las funciones tienen la misma longitud */
    if ( ( funcion1 -> longitud > 0 ) && ( funcion1 -> longitud == funcion2 -> longitud ) )
    {
    /* Si las funciones tienen el mismo grafo */
      if ( strcmp ( funcion1 -> graph_ecuation , funcion2 -> graph_ecuation ) == 0 )
      {
      /* Asumo que las funciones son iguales pero con cambios triviales */
        ret = TRUE;
      }
    }
  }

  return ( ret );
}

/****************************************************************************/

int es_funcion_patcheada ( Funcion *funcion1 , List &funciones_2 , Funcion **funcion2 )
{
  Basic_Block_Padre *basic_block_padre;
  Funcion *funcion_padre1;
  Funcion *funcion_padre2;
  unsigned int cont;
  int ret = FALSE;

/* Recorro todas las funciones padres de funcion1 */
  for ( cont = 0 ; cont < funcion1 -> cantidad_referencias_padre ; cont ++ )
  {
  /* Obtengo el basic block donde es llamada la funcion */
    basic_block_padre = &funcion1 -> basic_blocks_padres [ cont ];

  /* Obtengo la funcion padre que llama a la funcion */
    funcion_padre1 = ( Funcion * ) basic_block_padre -> funcion;

  /* Si la funcion padre fue relacionada con otra funcion en programa2 */
    if ( ( funcion_padre1 -> identica == TRUE ) || ( funcion_padre1 -> patcheada == TRUE ) )
    {
    /* Obtengo la funcion padre de 2 */
      funcion_padre2 = get_estructura_funcion ( funciones_2 , funcion_padre1 -> address_equivalente );

    /* Busco en las funciones padres el basic block en comun */
      ret = get_funcion_equivalente_x_grafo ( 0 , funcion_padre1 , funcion1 , NULL , funciones_2 , funcion_padre2 , funcion2 , NULL );

    /* Si encontre la funcion equivalente */
      if ( ret == TRUE )
      {
      /* Salgo */
        break;
      }
    }
  }

  return ( ret );
}

/****************************************************************************/

int get_funcion_equivalente_x_grafo ( int nivel , Funcion *funcion_padre1 , Funcion *funcion1 , Basic_Block *basic_block1 , List &funciones2 , Funcion *funcion_padre2 , Funcion **funcion2 , Basic_Block *basic_block2 )
{
  List basic_blocks_padres1;
  List basic_blocks_padres2;
  Funcion *funcion_buscada;
  Basic_Block *basic_block_padre1;
  Basic_Block *basic_block_padre2;
  Basic_Block *basic_block_hijo1;
  Basic_Block *basic_block_hijo2;
  int condicion_invertida = FALSE;
  unsigned int funcion2_address;
  unsigned int address_hija1;
  unsigned int address_hija2;
  unsigned int cont, cont2;
  unsigned int pos;
  int ret = FALSE;

/* Si estoy en el primer nivel */
  if ( nivel == 0 )
  {
  /* Marco como libre a todos los basic blocks de las funciones padres */
    liberar_basic_blocks ( funcion_padre1 );
    liberar_basic_blocks ( funcion_padre2 );

  /* Levanto los basic blocks iniciales */
    basic_block1 = funcion_padre1 -> basic_blocks [ 0 ];
    basic_block2 = funcion_padre2 -> basic_blocks [ 0 ];
  }

/* Marco los basic blocks como visitados */
  basic_block1 -> visitado = TRUE;
  basic_block2 -> visitado = TRUE;

/* Si los basic blocks tienen checksums distintos */
  if ( basic_block1 -> checksum != basic_block2 -> checksum )
  {
  /* Si tengo una condicion invertida */
    if ( is_condicion_invertida ( funcion_padre1 , funcion_padre2 , basic_block1 , basic_block2 ) == TRUE )
    {
    /* Condicion invertida detectada */
      condicion_invertida = TRUE;

//      my_msg ( "condicion invertida: %x - %x\n" , basic_block1 -> addr_inicial , basic_block2 -> addr_inicial );
    }
  /* Si NO es un camino confiable */
    else if ( is_camino_confiable ( 1 , 0 , funcion_padre1 , funcion_padre2 , basic_block1 , basic_block2 ) == FALSE )
    {
    /* No puedo seguir por este camino */
      return ( FALSE );
    }
  }

/* Busco en el basic block si estoy llamando a la funcion */
  if ( basic_block1 -> funciones_hijas -> GetPos ( ( void * ) funcion1 -> address , &pos ) == TRUE )
  {
  /* Si los basic blocks llaman a la misma cantidad de funciones */
    if ( basic_block1 -> funciones_hijas -> Len () == basic_block2 -> funciones_hijas -> Len () )
    {
    /* Levanto en la misma posicion de llamados en el basic block 2 */
      funcion2_address = ( unsigned int ) basic_block2 -> funciones_hijas -> Get ( pos );

    /* Obtengo la funcion */
      funcion_buscada = get_estructura_funcion ( funciones2 , funcion2_address ); 

    /* Si encontre la funcion equivalente */
      if ( funcion_buscada != NULL )
      {
      /* Si la funcion NO fue matcheada con otra */
        if ( ( funcion_buscada -> identica == FALSE ) && ( funcion_buscada -> patcheada == FALSE ) )
        {
        /* Retorno la funcion */
          *funcion2 = funcion_buscada;

        /* Retorno OK */
          return ( TRUE );
        }
      /* La funcion padre esta MAL asociada */
        else
        {
        /* Mensaje para mi */
//          my_msg ( "warning: possible bad asociation %x - %x\n" , funcion_padre1 -> address , funcion_padre2 -> address );
          my_msg ( "warning: possible bad asociation %x - %x\n" , funcion1 -> address , funcion_buscada -> address );
  
        /* NO PUEDO SEGUIR AVANZANDO */
          return ( FALSE );
        }
      }
    }
  }

/* Avanzo por todos los caminos hijos */
  for ( cont = 0 ; cont < basic_block1 -> basic_blocks_hijos -> Len () ; cont ++ )
  {
  /* Si NO hay condicion invertida */
    if ( condicion_invertida == FALSE )
    {
    /* Levanto las siguientes direcciones hijas */
      address_hija1 = ( unsigned int ) basic_block1 -> basic_blocks_hijos -> Get ( cont );
      address_hija2 = ( unsigned int ) basic_block2 -> basic_blocks_hijos -> Get ( cont );
    }
  /* Si tengo una condicion invertida */
    else
    {
    /* Si estoy llendo por el camino del positivo */
      if ( cont == 0 )
      {
      /* Levanto las siguientes direcciones hijas */
        address_hija1 = ( unsigned int ) basic_block1 -> basic_blocks_hijos -> Get ( cont );
        address_hija2 = ( unsigned int ) basic_block2 -> basic_blocks_hijos -> Get ( cont + 1 );
      }
      else
      {
      /* Levanto las siguientes direcciones hijas */
        address_hija1 = ( unsigned int ) basic_block1 -> basic_blocks_hijos -> Get ( cont );
        address_hija2 = ( unsigned int ) basic_block2 -> basic_blocks_hijos -> Get ( cont - 1 );
      }
    }

  /* Obtengo los basic block hijos */
    basic_block_hijo1 = get_basic_block_from_array ( funcion_padre1 -> basic_blocks , funcion_padre1 -> cantidad_basic_blocks , address_hija1 );
    basic_block_hijo2 = get_basic_block_from_array ( funcion_padre2 -> basic_blocks , funcion_padre2 -> cantidad_basic_blocks , address_hija2 );

  /* Si los 2 basic blocks estan LIBRES */
    if ( ( basic_block_hijo1 -> visitado == FALSE ) && ( basic_block_hijo2 -> visitado == FALSE ) )
    {
    /* Avanzo por este camino */
      ret = get_funcion_equivalente_x_grafo ( nivel + 1 , funcion_padre1 , funcion1 , basic_block_hijo1 , funciones2 , funcion_padre2 , funcion2 , basic_block_hijo2 );

    /* Si encontre la funcion */
      if ( ret == TRUE )
      {
      /* Retorno OK */
        return ( TRUE );
      }
    }
  }

/* Dejo para mas adelante recorrer la funcion hacia arriba */
  return ( ret );

/////////////////////////////////////////////

/* Si NO pude encontrar la funcion */
  if ( ret == FALSE )
  {
  /* Obtengo todos los basic blocks padres */
    get_basic_blocks_padres ( funcion_padre1 , basic_block1 , basic_blocks_padres1 );
    get_basic_blocks_padres ( funcion_padre2 , basic_block2 , basic_blocks_padres2 );

  /* Recorro todos los basic blocks padres 1 */
    for ( cont = 0 ; cont < basic_blocks_padres1.Len () ; cont ++ )
    {
    /* Levanto el siguiente basic block */
      basic_block_padre1 = ( Basic_Block * ) basic_blocks_padres1.Get ( cont );

    /* Si el basic block fue visitado */
      if ( basic_block_padre1 -> visitado == TRUE )
      {
      /* Sigo buscando */
        continue;
      }

    /* Recorro todos los basic blocks padres de 2 */
      for ( cont2 = 0 ; cont2 < basic_blocks_padres2.Len () ; cont2 ++ )
      {
      /* Levanto el siguiente basic block */
        basic_block_padre2 = ( Basic_Block * ) basic_blocks_padres2.Get ( cont2 );

      /* Si el basic block fue visitado */
        if ( basic_block_padre2 -> visitado == TRUE )
        {
        /* Sigo buscando */
          continue;
        }

      /* Si los 2 basic blocks tienen el mismo checksum */
        if ( basic_block_padre1 -> checksum == basic_block_padre2 -> checksum )
        {
        /* Si los 2 basic blocks tienen la misma cantidad de hijos */
          if ( basic_block_padre1 -> funciones_hijas -> Len () == basic_block_padre2 -> funciones_hijas -> Len () )
          {
          /* Avanzo hacia arriba por este camino */
            ret = get_funcion_equivalente_x_grafo ( nivel + 1 , funcion_padre1 , funcion1 , basic_block_padre1 , funciones2 , funcion_padre2 , funcion2 , basic_block_padre2 );

          /* Si encontre la funcion */
            if ( ret == TRUE )
            {
            /* Retorno OK */
              return ( TRUE );
            }
          }
        }
      }
    }
  }

  return ( ret );
}

/****************************************************************************/

int is_condicion_invertida ( Funcion *funcion1 , Funcion *funcion2 , Basic_Block *basic_block1 , Basic_Block *basic_block2 )
{
  Basic_Block *basic_block_hijo11;
  Basic_Block *basic_block_hijo12;
  Basic_Block *basic_block_hijo21;
  Basic_Block *basic_block_hijo22;
  unsigned int address_hija1;
  unsigned int address_hija2;
  int ret = FALSE;

/* Si los basic blocks tienen checksums distintos */
  if ( basic_block1 -> checksum != basic_block2 -> checksum )
  {
  /* Si los basic blocks tienen la misma longitud */
    if ( basic_block1 -> longitud == basic_block2 -> longitud )
    {
    /* Si los basic blocks actuales tienen 2 hijos */
      if ( ( basic_block1 -> basic_blocks_hijos -> Len () == 2 ) && ( basic_block1 -> basic_blocks_hijos -> Len () == basic_block2 -> basic_blocks_hijos -> Len () ) )
      {
      /* Obtengo los basic blocks hijos de 1 */
        address_hija1 = ( unsigned int ) basic_block1 -> basic_blocks_hijos -> Get ( 0 );
        basic_block_hijo11 = get_basic_block_from_array ( funcion1 -> basic_blocks , funcion1 -> cantidad_basic_blocks , address_hija1 );
        address_hija1 = ( unsigned int ) basic_block1 -> basic_blocks_hijos -> Get ( 1 );
        basic_block_hijo12 = get_basic_block_from_array ( funcion1 -> basic_blocks , funcion1 -> cantidad_basic_blocks , address_hija1 );

      /* Obtengo los basic blocks hijos de 2 */
        address_hija2 = ( unsigned int ) basic_block2 -> basic_blocks_hijos -> Get ( 0 );
        basic_block_hijo21 = get_basic_block_from_array ( funcion2 -> basic_blocks , funcion2 -> cantidad_basic_blocks , address_hija2 );
        address_hija2 = ( unsigned int ) basic_block2 -> basic_blocks_hijos -> Get ( 1 );
        basic_block_hijo22 = get_basic_block_from_array ( funcion2 -> basic_blocks , funcion2 -> cantidad_basic_blocks , address_hija2 );

      /* Si los basic blocks tienen checksums distintos */
        if ( basic_block_hijo11 -> checksum != basic_block_hijo21 -> checksum )
        {
        /* Si las referencias estan cruzadas */
          if ( ( basic_block_hijo11 -> checksum == basic_block_hijo22 -> checksum ) && ( basic_block_hijo12 -> checksum == basic_block_hijo21 -> checksum ) )
          {
          /* Condicion invertida detectada */
            ret = TRUE;
          }
        }
      }
    }
  }

  return ( ret );
}

/****************************************************************************/

int is_camino_confiable ( unsigned int profundidad_maxima, unsigned int profundidad , Funcion *funcion1 , Funcion *funcion2 , Basic_Block *basic_block1 , Basic_Block *basic_block2 )
{
  Basic_Block *basic_block_hijo1;
  Basic_Block *basic_block_hijo2;
  unsigned int address_hija1;
  unsigned int address_hija2;
  unsigned int cont;
  int ret = FALSE;

/* Si los basic blocks actuales son IDENTICOS */
  if ( basic_block1 -> checksum == basic_block2 -> checksum )
  {
  /* Retorno OK */
    return ( TRUE );
  }

/* Si llegue a la profundidad maxima */
  if ( profundidad == profundidad_maxima )
  {
  /* Chequeo que los basic blocks coincidan */
    if ( basic_block1 -> checksum == basic_block2 -> checksum )
    {
    /* Retorno OK */
      return ( TRUE );
    }
    else
    {
    /* Retorno ERROR */
      return ( FALSE );
    }
  }

/* Si los basic blocks tienen distinta cantidad de hijos */
  if ( basic_block1 -> basic_blocks_hijos -> Len () != basic_block2 -> basic_blocks_hijos -> Len () )
  {
  /* Retorno ERROR */
    return ( FALSE );
  }

/* Recorro todas las conexiones hijas */
  for ( cont = 0 ; cont < basic_block1 -> basic_blocks_hijos -> Len () ; cont ++ )
  {
  /* Levanto la direccion de los siguientes basic blocks hijos */
    address_hija1 = ( unsigned int ) basic_block1 -> basic_blocks_hijos -> Get ( cont );
    address_hija2 = ( unsigned int ) basic_block2 -> basic_blocks_hijos -> Get ( cont );

  /* Levanto los siguientes basic blocks hijos */
    basic_block_hijo1 = get_basic_block_from_array ( funcion1 -> basic_blocks , funcion1 -> cantidad_basic_blocks , address_hija1 );
    basic_block_hijo2 = get_basic_block_from_array ( funcion2 -> basic_blocks , funcion2 -> cantidad_basic_blocks , address_hija2 );

  /* Avanzo por este camino */
    ret = is_camino_confiable ( profundidad_maxima , profundidad + 1 , funcion1 , funcion2 , basic_block_hijo1 , basic_block_hijo2 );

  /* Si el camino NO es confiable */
    if ( ret == FALSE )
    {
    /* Retorno ERROR */
      return ( FALSE );
    }
  }

  return ( ret );
}

/****************************************************************************/

int get_funcion_equivalente_x_hijos ( Funcion *funcion1 , List &funciones1 , List &funciones2 , Funcion **funcion2 )
{
  int ret;

/* Intento resolver por padres en comun de los hijos */
  ret = get_funcion_equivalente_x_hijos_x_padres_en_comun ( funcion1 , funciones1 , funciones2 , funcion2 );

/* Si no lo pude sacar, intento resolverlo buscando un hijo que le falte este padre */
  if ( ret == FALSE )
  {
    ret = get_funcion_equivalente_x_hijos_x_unico_padre ( funcion1 , funciones1 , funciones2 , funcion2 );

    if ( ret == TRUE )
    {
//      my_msg ( "un solo padre: %x - %x\n" , funcion1 -> address , ( *funcion2 ) -> address );
    }
  }

  return ( ret );
}

/****************************************************************************/

int get_funcion_equivalente_x_hijos_x_padres_en_comun ( Funcion *funcion1 , List &funciones1 , List &funciones2 , Funcion **funcion2 )
{
  List funciones_padre2;
  List funciones_padre2_interseccion;
  Basic_Block *basic_block;
  Basic_Block_Padre *basic_block_padre2;
  Funcion *funcion_hija;
  Funcion *funcion_hija2;
  Funcion *funcion_padre2;
  unsigned int cont, cont2, cont3;
  int primera_iteracion = TRUE;
  int ret = FALSE;

/* Recorro todos los basic blocks */
  for ( cont = 0 ; cont < funcion1 -> cantidad_basic_blocks ; cont ++ )
  {
  /* Levanto el siguiente basic block */
    basic_block = funcion1 -> basic_blocks [ cont ];

  /* Recorro todas las referencias hijas del basic block */
    for ( cont2 = 0 ; cont2 < basic_block -> funciones_hijas -> Len () ; cont2 ++ )
    {
    /* Levanto la siguiente funcion */
      funcion_hija = get_estructura_funcion ( funciones1 , ( unsigned int ) basic_block -> funciones_hijas -> Get ( cont2 ) );

    /* Si la funcion existe */
      if ( funcion_hija != NULL )
      {
      /* Si la funcion hija fue reconocida */
        if ( ( funcion_hija -> identica == TRUE ) || ( funcion_hija -> patcheada == TRUE ) )
        {
        /* Levanto la funcion hija en programa 2 */
          funcion_hija2 = get_estructura_funcion ( funciones2 , funcion_hija -> address_equivalente );

        /* Recorro todos los basic blocks padres */
          for ( cont3 = 0 ; cont3 < funcion_hija2 -> cantidad_referencias_padre ; cont3 ++ )
          {
          /* Levanto el proximo basic block padre */
            basic_block_padre2 = &funcion_hija2 -> basic_blocks_padres [ cont3 ];

          /* Levanto la funcion a la que pertenece */
            funcion_padre2 = ( Funcion * ) basic_block_padre2 -> funcion;

          /* Si la funcion padre de funcion2 no fue reconocida */  
            if ( ( funcion_padre2 -> identica == FALSE ) && ( funcion_padre2 -> patcheada == FALSE ) )
            {
            /* Si es la primera iteracion, armo la lista inicial */
              if ( primera_iteracion == TRUE )
              {
              /* Si la funcion no fue agregada ( una funcion puede llamar varias veces a otra ) */
                if ( funciones_padre2.Find ( funcion_padre2 ) == FALSE )
                {
                /* Agrego el elemento a la lista */
                  funciones_padre2.Add ( funcion_padre2 );
                }
              }
            /* Comienzo a quedarme con los elementos en comun */
              else
              {
              /* Si la funcion padre esta en la lista anterior */
                if ( funciones_padre2.Find ( funcion_padre2 ) == TRUE )
                {
                /* Si la funcion no fue agregada ( una funcion puede llamar varias veces a otra ) */
                  if ( funciones_padre2_interseccion.Find ( funcion_padre2 ) == FALSE )
                  {
                 /* Agrego el elemento a la lista */
                    funciones_padre2_interseccion.Add ( funcion_padre2 );
                  }
                }
              }
            }
          }

        /* Si no es la primera vez, libero la lista vieja */
          if ( primera_iteracion == FALSE )
          {
            funciones_padre2.Clear ();

          /* Paso la lista de intersecciones a la lista comun */
            for ( cont3 = 0 ; cont3 < funciones_padre2_interseccion.Len () ; cont3 ++ )
            {
            /* Levanto el siguiente elemento y lo agrego a la lista */
              funciones_padre2.Add ( funciones_padre2_interseccion.Get ( cont3 ) );
            }

          /* Libero la lista de intersecciones */
            funciones_padre2_interseccion.Clear ();
          }
        }
//      /* No puedo confiar si no tengo todas las funciones hijas reconocidas */
//        else
//        {
//          my_msg ( "me quede sin padres en funcion %x - hijo %x\n" , funcion1 -> address , funcion_hija -> address );
//
//        /* No pude encontrar la funcion equivalente */
//          return ( FALSE );
//        }

      /* Anulo la condicion despues de procesar la primera funcion hija */
        primera_iteracion = FALSE;
      }
    /* Algo no esta bien */
      else
      {
        my_msg ( "inconsistencia en la funcion %x, bb %x, hija %x\n" , funcion1 -> address , basic_block -> addr_inicial , ( unsigned int ) basic_block -> funciones_hijas -> Get ( cont2 ) );
      }
    }
  }

/* Si me quedo el padre en comun */
  if ( funciones_padre2.Len () == 1 )
  {
//    my_msg ( "wiiiiiiiiiiiiiiiiiiiii\n" );

  /* Retorno la funcion equivalente en programa 2 */
    *funcion2 = ( Funcion * ) funciones_padre2.Get ( 0 );

  /* Retorno OK */
    ret = TRUE;
  }
  else
  {
//    my_msg ( "saliendo con %i padres \n" , funciones_padre2.Len () );
  }

  return ( ret );
}

/****************************************************************************/

int get_funcion_equivalente_x_hijos_x_unico_padre ( Funcion *funcion1 , List &funciones1 , List &funciones2 , Funcion **funcion2 )
{
  Basic_Block *basic_block;
  Basic_Block_Padre *basic_block_padre2;
  Funcion *funcion_hija;
  Funcion *funcion_hija2;
  Funcion *funcion_padre2;
  Funcion *funcion2_candidata;
  unsigned int cont, cont2, cont3;
  int padre_detectado = FALSE;
  int ret = FALSE;

/* Recorro todos los basic blocks */
  for ( cont = 0 ; cont < funcion1 -> cantidad_basic_blocks ; cont ++ )
  {
  /* Levanto el siguiente basic block */
    basic_block = funcion1 -> basic_blocks [ cont ];

  /* Recorro todas las referencias hijas del basic block */
    for ( cont2 = 0 ; cont2 < basic_block -> funciones_hijas -> Len () ; cont2 ++ )
    {
    /* Levanto la siguiente funcion */
      funcion_hija = get_estructura_funcion ( funciones1 , ( unsigned int ) basic_block -> funciones_hijas -> Get ( cont2 ) );

    /* Si la funcion existe */
      if ( funcion_hija != NULL )
      {
      /* Si la funcion hija fue reconocida */
        if ( ( funcion_hija -> identica == TRUE ) || ( funcion_hija -> patcheada == TRUE ) )
        {
        /* Levanto la funcion hija en programa 2 */
          funcion_hija2 = get_estructura_funcion ( funciones2 , funcion_hija -> address_equivalente );

        /* Recorro todos los basic blocks padres */
          for ( cont3 = 0 ; cont3 < funcion_hija2 -> cantidad_referencias_padre ; cont3 ++ )
          {
          /* Levanto el proximo basic block padre */
            basic_block_padre2 = &funcion_hija2 -> basic_blocks_padres [ cont3 ];

          /* Levanto la funcion a la que pertenece */
            funcion_padre2 = ( Funcion * ) basic_block_padre2 -> funcion;

          /* Si la funcion padre de funcion2 no fue reconocida */
            if ( ( funcion_padre2 -> identica == FALSE ) && ( funcion_padre2 -> patcheada == FALSE ) )
            {
            /* Si es el primer candidato */
              if ( padre_detectado == FALSE )
              {
              /* Aca tengo un candidato */
                funcion2_candidata = funcion_padre2;

              /* Para que no vuelva a entrar */
                padre_detectado = TRUE;

              /* Marco la salida como OK */
                ret = TRUE;
              }
            /* Si tengo mas de un candidato NO me sirve */
              else
              {
                return ( FALSE );
              }
            }
          }
        }
      }
    }
  }

/* Si encontre un candidato */
  if ( ret == TRUE )
  {
  /* Retorno la funcion par que encontre */
    *funcion2 = funcion2_candidata;
  }

  return ( ret );
}

/****************************************************************************/

int clasificar_funciones_cambiadas ( List &funciones1_cambiadas , List &funciones2_cambiadas , List &funciones1_matcheadas , List &funciones2_matcheadas )
{
  Funcion *funcion1;
  Funcion *funcion2;
  unsigned int cont;
  int ret = TRUE;

/* Recorro todas las funciones cambiadas */
  for ( cont = 0 ; cont < funciones1_cambiadas.Len () ; cont ++ )
  {
  /* Levanto funcion1 */
    funcion1 = ( Funcion * ) funciones1_cambiadas.Get ( cont );

  /* Levanto funcion2 */
    funcion2 = ( Funcion * ) funciones2_cambiadas.Get ( cont );

  /* Si las 2 funciones tienen la misma cantida de instrucciones y son geometricamente identicas */
    if ( son_funciones_cuasi_identicas ( funcion1 , funcion2 ) == TRUE )
    {
    /* Saco las funciones de la lista de cambiadas */
      funciones1_cambiadas.Delete ( cont );
      funciones2_cambiadas.Delete ( cont );

    /* Agrego las funciones a la lista de funciones con cambios triviales */
      funciones1_matcheadas.Add ( ( void * ) funcion1 );
      funciones2_matcheadas.Add ( ( void * ) funcion2 );

    /* Complemento la extraccion del elemento */
      cont --;
    }
  /* Si las 2 funciones tienen el mismo grafo, puedo asumir que NO tiene cambios importantes */
    else if ( strcmp ( funcion1 -> graph_ecuation , funcion2 -> graph_ecuation ) == 0 )
    {
    /* Saco las funciones de la lista de cambiadas */
      funciones1_cambiadas.Delete ( cont );
      funciones2_cambiadas.Delete ( cont );

    /* Agrego las funciones a la lista de funciones con cambios triviales */
      funciones1_geometricamente_identicas.Add ( ( void * ) funcion1 );
      funciones2_geometricamente_identicas.Add ( ( void * ) funcion2 );

    /* Complemento la extraccion del elemento */
      cont --;
    }
  }

  return ( ret );
}

/****************************************************************************/

int armar_resultados ( void )
{
  Funcion *funcion1;
  Funcion *funcion2;
  unsigned int cont;
  int ret = TRUE;

/* Funciones identicas */
  for ( cont = 0 ; cont < funciones1_reconocidas.Len () ; cont ++ )
  {
  /* Levanto las funciones IDENTICAS */
    funcion1 = ( Funcion * ) funciones1_reconocidas.Get ( cont );
    funcion2 = ( Funcion * ) funciones2_reconocidas.Get ( cont );

  /* Agrego el tipo de matcheo a la lista */
    matcheo_1_2.Add ( ( void * ) IDENTICAL_MATCH );

  /* Agrego la direccion de las funciones a las listas */
    resultado1.Add ( ( void * ) funcion1 -> address );
    resultado2.Add ( ( void * ) funcion2 -> address );
  }

//////////////////////////////

/* Funciones con grafo identico, misma cantidad de instrucciones */
  for ( cont = 0 ; cont < funciones1_matcheadas.Len () ; cont ++ )
  {
  /* Levanto las funciones MATCHEADAS */
    funcion1 = ( Funcion * ) funciones1_matcheadas.Get ( cont );
    funcion2 = ( Funcion * ) funciones2_matcheadas.Get ( cont );

  /* Agrego el tipo de matcheo a la lista */
    matcheo_1_2.Add ( ( void * ) CHANGED_1_MATCH );

  /* Agrego la direccion de las funciones a las listas */
    resultado1.Add ( ( void * ) funcion1 -> address );
    resultado2.Add ( ( void * ) funcion2 -> address );
  }

//////////////////////////////

/* Funciones con grafo identico */
  for ( cont = 0 ; cont < funciones1_geometricamente_identicas.Len () ; cont ++ )
  {
  /* Levanto las funciones GEOMETRICAMENTE IDENTICAS */
    funcion1 = ( Funcion * ) funciones1_geometricamente_identicas.Get ( cont );
    funcion2 = ( Funcion * ) funciones2_geometricamente_identicas.Get ( cont );

  /* Agrego el tipo de matcheo a la lista */
    matcheo_1_2.Add ( ( void * ) CHANGED_2_MATCH );

  /* Agrego la direccion de las funciones a las listas */
    resultado1.Add ( ( void * ) funcion1 -> address );
    resultado2.Add ( ( void * ) funcion2 -> address );
  }

//////////////////////////////

/* Funciones con grafo distinto */
  for ( cont = 0 ; cont < funciones1_cambiadas.Len () ; cont ++ )
  {
  /* Levanto las funciones MATCHEADAS POR CALL GRAPH */
    funcion1 = ( Funcion * ) funciones1_cambiadas.Get ( cont );
    funcion2 = ( Funcion * ) funciones2_cambiadas.Get ( cont );

  /* Agrego el tipo de matcheo a la lista */
    matcheo_1_2.Add ( ( void * ) CHANGED_3_MATCH );

  /* Agrego la direccion de las funciones a las listas */
    resultado1.Add ( ( void * ) funcion1 -> address );
    resultado2.Add ( ( void * ) funcion2 -> address );
  }

//////////////////////////////

/* Funciones de programa 1 que no pudieron asociarse */
  for ( cont = 0 ; cont < funciones1_irreconocidas.Len () ; cont ++ )
  {
  /* Levanto las funciones GEOMETRICAMENTE IDENTICAS */
    funcion1 = ( Funcion * ) funciones1_irreconocidas.Get ( cont );

  /* Agrego el tipo de matcheo a la lista */
    matcheo_1_2.Add ( ( void * ) UNMATCHED1_MATCH );

  /* Agrego la direccion de las funciones a las listas */
    resultado1.Add ( ( void * ) funcion1 -> address );
    resultado2.Add ( ( void * ) NULL );
  }

//////////////////////////////

/* Funciones de programa2 que no pudieron asociarse */
  for ( cont = 0 ; cont < funciones2_irreconocidas.Len () ; cont ++ )
  {
  /* Levanto las funciones GEOMETRICAMENTE IDENTICAS */
    funcion2 = ( Funcion * ) funciones2_irreconocidas.Get ( cont );

  /* Agrego la direccion de las funciones a las listas */
    matcheo_1_2.Add ( ( void * ) UNMATCHED2_MATCH );

  /* Agrego la direccion de las funciones a las listas */
    resultado1.Add ( ( void * ) NULL );
    resultado2.Add ( ( void * ) funcion2 -> address );
  }

//////////////////////////////

  return ( ret );
}

/****************************************************************************/

int guardar_resultados ( char *file1 , char *file2 )
{
  char file2_copy [ QMAXPATH ];
  char *file2_name;
  char *point;
  FILE *f;
  int ret;

/* Me hago una copia del nombre completo de file1 */
  qstrncpy ( result_file , file1 , QMAXPATH );

/* Ubico el nombre de file2 */
  file2_name = strrchr ( file2 , '\\' );

/* Hago una copia del nombre file2 */
  qstrncpy ( file2_copy , file2_name + 1 , QMAXPATH );

/* Ubico el punto que separa el nombre de la extension */
  point = strrchr ( file2_copy , '.' );

/* Cierro el string donde esta el punto */
  *point = '\0';

/* Armo el nombre del file donde van a ir a parar los resultados */
  change_extension ( result_file , file2_copy );

/* Abro el archivo */
  f = qfopen ( result_file , "wb" );

/* Si pude abrir el archivo */
  if ( f != NULL )
  {
  /* Guardo las listas en el file */
    matcheo_1_2.Save ( f );
    resultado1.Save ( f );
    resultado2.Save ( f );

  /* Cierro el archivo */
    qfclose ( f );

  /* Retorno OK */
    ret = TRUE;
  }
  else
  {
  /* Retorno ERROR */
    ret = FALSE;
  }

  return ( ret );
}

/****************************************************************************/

int levantar_resultados ( char *file1 , char *file2 )
{
  char result_file [ QMAXPATH ];
  char file2_copy [ QMAXPATH ];
  char *file2_name;
  char *point;
  FILE *f;
  int ret;

/* Me hago una copia del nombre completo de file1 */
  qstrncpy ( result_file , file1 , QMAXPATH );

/* Ubico el nombre de file2 */
  file2_name = strrchr ( file2 , '\\' );

/* Hago una copia del nombre file2 */
  qstrncpy ( file2_copy , file2_name + 1 , QMAXPATH );

/* Ubico el punto que separa el nombre de la extension */
  point = strrchr ( file2_copy , '.' );

/* Cierro el string donde esta el punto */
  *point = '\0';

/* Armo el nombre del file donde van a ir a parar los resultados */
  change_extension ( result_file , file2_copy );

/* Abro el archivo */
  f = qfopen ( result_file , "rb" );

/* Si pude abrir el archivo */
  if ( f != NULL )
  {
  /* Levanto las listas desde el file */
    matcheo_1_2.Load ( f );
    resultado1.Load ( f );
    resultado2.Load ( f );

  /* Cierro el archivo */
    qfclose ( f );

  /* Retorno OK */
    ret = TRUE;
  }
  else
  {
  /* Retorno ERROR */
    ret = FALSE;
  }

  return ( ret );
}

/****************************************************************************/

int mostrar_resultados ( char *file1 , char *file2 )
{
  Funcion *funcion1;
  Funcion *funcion2;
  unsigned int match_value;
  unsigned int address1;
  unsigned int address2;
  int pos = 0;
  int ret = TRUE;

/* Espero que el usuario elija alguna opcion */
  while ( ( pos = mostrar_funciones ( pos + 1 ) ) != -1 )
  {
  /* Obtengo el valor de matcheo */
    match_value = ( unsigned int ) matcheo_1_2.Get ( pos );

  /* Si NO son funciones UNMATCHEDs */
    if ( ( match_value != UNMATCHED1_MATCH ) && ( match_value != UNMATCHED2_MATCH ) )
    {
    /* Obtengo la direccion de las funciones matcheadas */
      address1 = ( unsigned int ) resultado1.Get ( pos );
      address2 = ( unsigned int ) resultado2.Get ( pos );

    /* Levanto las funciones */
      funcion1 = get_estructura_funcion ( funciones1 , address1 );
      funcion2 = get_estructura_funcion ( funciones2 , address2 );

    /* Diffeo las 2 funciones */
      diffear_y_mostrar_funciones ( file1 , file2 , funcion1 , funcion2 );
    }
    else
    {
    /* Mensaje al usuario */
      my_msg ( "Don't choose unmatched functions !\n" );
    }
  }

  return ( ret );
}

/****************************************************************************/
/****************************************************************************/

void idaapi armar_columnas ( void *obj , unsigned int columna , char *arrptr [] )
{
  char *match_types [] = { "identical" , "suspicious +" , "suspicious ++" , "changed" , "unmatched 1" , "unmatched 2" };
  char *match_type;
  char name1 [ 256 ];
  char name2 [ 256 ];
  Funcion *funcion1;
  Funcion *funcion2;
  unsigned int address1;
  unsigned int address2;
  unsigned int match_value;
  unsigned int pos;

/* Si es la primera llamada */
/* Armo el nombre de las columnas */
  if ( columna == 0 )
  {
    qstrncpy ( arrptr [ 0 ] , "category" , QMAXPATH );
    qstrncpy ( arrptr [ 1 ] , "address" , QMAXPATH );  
    qstrncpy ( arrptr [ 2 ] , "name" , QMAXPATH );  
    qstrncpy ( arrptr [ 3 ] , "address" , QMAXPATH );  
    qstrncpy ( arrptr [ 4 ] , "name" , QMAXPATH );  
  }
/* Lleno el contenido de las columnas */
  else
  {
  /* Normalizo al posicion */
    pos = columna - 1;

  /* Valor de matcheo */
    match_value = ( unsigned int ) matcheo_1_2.Get ( pos );

  /* Obtengo el tipo de matcheo */
    match_type = match_types [ match_value ];

  /* Obtengo la direccion de las funciones matcheadas */
    address1 = ( unsigned int ) resultado1.Get ( pos );
    address2 = ( unsigned int ) resultado2.Get ( pos );

  /* Levanto las funciones */
    funcion1 = get_estructura_funcion ( funciones1 , address1 );
    funcion2 = get_estructura_funcion ( funciones2 , address2 );

  /* Pongo la categoria */
    qsnprintf ( arrptr [ 0 ] , 14 , match_type );

  /* Si es una funcion de programa2 que no matcheo */
    if ( match_value != UNMATCHED2_MATCH )
    {
    /* Obtengo el nombre de la funcion */
      get_formated_name ( funcion1 , name1 , 256 , FALSE );

    /* Pongo la direccion de funcion1 */
      qsnprintf ( arrptr [ 1 ] , 10 , "%x" , funcion1 -> address );

    /* Pongo la direccion de funcion1 */
      qsnprintf ( arrptr [ 2 ] , NAME_LEN , "%s" , name1 );
    }
    else
    {
    /* Pongo la direccion de funcion1 */
      qsnprintf ( arrptr [ 1 ] , 10 , "-" );

    /* Pongo la direccion de funcion1 */
      qsnprintf ( arrptr [ 2 ] , NAME_LEN , "-" );
    }

  /* Si es una funcion de programa1 que no matcheo */
    if ( match_value != UNMATCHED1_MATCH )
    {
    /* Obtengo el nombre de la funcion */
      get_formated_name ( funcion2 , name2 , 256 , FALSE );

    /* Pongo la direccion de funcion2 */
      qsnprintf ( arrptr [ 3 ] , 10 , "%x" , funcion2 -> address );

    /* Pongo la direccion de funcion2 */
      qsnprintf ( arrptr [ 4 ] , NAME_LEN , "%s" , name2 );
    }
    else
    {
    /* Pongo la direccion de funcion2 */
      qsnprintf ( arrptr [ 3 ] , 10 , "-" );

    /* Pongo la direccion de funcion2 */
      qsnprintf ( arrptr [ 4 ] , NAME_LEN , "-" );
    }
  }
}

/****************************************************************************/

unsigned int idaapi retornar_size ( void *obj )
{
  return ( resultado1.Len () );
}

/****************************************************************************/

void idaapi enter_function ( void *obj , unsigned int columna )
{
  my_msg ( "columna: %i\n" , columna );
}

/****************************************************************************/

void idaapi destroy_function ( void *obj )
{
}

/****************************************************************************/

unsigned int mostrar_funciones ( unsigned int pos )
{
  int anchos [] = { 14 , 10 , 30 , 10 , 30 };
  unsigned int ret;

  ret = my_choose (
            true,
            -1, -1, -1, -1,
            NULL,                         // node
            5,                            // numero de columnas
            anchos,                       // ancho de columnas
            ( void * ) retornar_size,     // callback a funcion que retorna n de lineas
            ( void * ) armar_columnas,    // callback description
//            "hola manola",              // Titulo
//            -1,
//            1,
//            NULL,
//            NULL,
//            NULL,
//            NULL,
            ( void * ) enter_function,    // enter callback
            ( void * ) destroy_function,   // destroy callback
//            NULL,
//            NULL
              pos
          );

/* Retorno la posicion donde el usuario apreto ENTER */
  return ( ret - 1 );
}

/****************************************************************************/

int diffear_funciones ( int comparar_por_pares , char *file1 , char *file2 )
{
  unsigned int file1_version;
  unsigned int file2_version;
  unsigned int address1;
  unsigned int address2;
  Funcion *funcion1;
  Funcion *funcion2;
  FILE *f1;
  FILE *f2;
  int ret = FALSE;

/* Intento abrir los 2 files de analisis */
  f1 = qfopen ( file1 , "rb" );
  f2 = qfopen ( file2 , "rb" );

/* Si NO pude abrir alguno de los files */
  if ( f1 == NULL || f2 == NULL )
  {
  /* Mensaje de ERROR al usuario */
    my_msg ( "ERROR: analized files don't exist !\n" );

  /* Salgo */
    return ( FALSE );
  }

/* Leo la version de los files */
  qfread ( f1 , ( void * ) &file1_version , sizeof ( unsigned int ) );
  qfread ( f2 , ( void * ) &file2_version , sizeof ( unsigned int ) );

/* Si alguna de las versiones NO coincide con la actual */
  if ( ( file1_version != turbodiff_version ) || ( file2_version != turbodiff_version ) )
  {
  /* Mensaje al usuario */
    my_msg ( "ERROR: Different file versions, please take the analysis again\n" );

  /* Retorno ERROR */
    return ( FALSE );
  }

/* Mensaje al usuario */
  my_msg ( "loading functions to compare ...\n" );

/* Levanto los 2 archivos */
  levantar_funciones ( f1 , indice_funciones1 , funciones1 );
  levantar_funciones ( f2 , indice_funciones2 , funciones2 );

/* Si quiero comparar las funciones via la lista de matcheos */
  if ( comparar_por_pares == TRUE )
  {
  /* Levanto los resultados */
    levantar_resultados ( file1 , file2 );

  /* Muestro los resultados */
    mostrar_resultados ( file1 , file2 );
  }
  else
  {
  /* Pido al usuario las funciones a comparar */
    while ( my_AskUsingForm ( funciones_a_comparar , &address1 , &address2 ) == 1 )
    {
    /* Levanto las funciones analizadas */
      funcion1 = get_estructura_funcion2 ( indice_funciones1 , funciones1 , address1 );    
      funcion2 = get_estructura_funcion2 ( indice_funciones2 , funciones2 , address2 );    
  
    /* Si pude obtener las 2 funciones */
      if ( ( funcion1 != NULL ) && ( funcion2 != NULL ) )
      {
      /* Diffeo las 2 funciones y las muestro */
        diffear_y_mostrar_funciones ( file1 , file2 , funcion1 , funcion2 );
      }
    /* Si alguna funcion no pudo ser localizada */
      else
      {
      /* Mensaje de ERROR al usuario */
        my_msg ( "ERROR: the function %x or function %x don't exist !\n" , address1 , address2 );
      }
    }
  }

/* Cierro los 2 files */
  qfclose ( f1 );
  qfclose ( f2 );

  return ( ret );
}

/****************************************************************************/

int diffear_y_mostrar_funciones ( char *file1 , char *file2 , Funcion *funcion1 , Funcion *funcion2 )
{
  char file1_dis [ QMAXPATH ];
  char file2_dis [ QMAXPATH ];
  char graph1 [ QMAXPATH ];
  char graph2 [ QMAXPATH ];
  int ret = TRUE;

/* Mensaje al usuario */
  my_msg ( "diffing %x - %x ...\n" , funcion1 -> address , funcion2 -> address );

/* Asocio los basic blocks de las 2 funciones */
  diffear_funcion_por_grafo ( funcion1 , funcion2 );

/* Hago una copia del nombre de los files */
  qstrncpy ( file1_dis , file1 , QMAXPATH );
  qstrncpy ( file2_dis , file2 , QMAXPATH );

/* Reemplazo el nombre de los files */
  change_extension ( file1_dis , "dis" );
  change_extension ( file2_dis , "dis" );

/* Obtengo los paths completos para generar los grafos de salida */
  get_ida_path ( QMAXPATH , graph1 );
  get_ida_path ( QMAXPATH , graph2 );
  qstrncat ( graph1 , "\\graph1.gdl" , QMAXPATH );
  qstrncat ( graph2 , "\\graph2.gdl" , QMAXPATH );

/* Genero los 2 archivos con los grafos */
  armar_grafo_salida ( "turbodiff - 1" , graph1 , file1_dis , funcion1 );
  armar_grafo_salida ( "turbodiff - 2" , graph2 , file2_dis , funcion2 );

/* Mensaje al usuario */
  my_msg ( "generating graph views ...\n" );

/* Si tengo que graficar con wingraph */
  if ( viewer_names.Len () == 0 )
  {
  /* Muestro el grafo de la funcion1 en el wingraph32.exe */
    mostrar_grafo ( graph1 );

  /* Muestro el grafo de la funcion2 en el wingraph32.exe */
    mostrar_grafo ( graph2 );
  }
/* Si tengo que graficar con el viewer de Aureliano */
  else
  {
  /* Muestro las funciones con el viewer de Aureliano */
    mostrar_grafos ( graph1 , graph2 );
  }

  return ( ret );
}

/****************************************************************************/

int diffear_funcion_por_grafo ( Funcion *funcion1 , Funcion *funcion2 )
{
  Basic_Block *basic_block1;
  Basic_Block *basic_block2;
  unsigned int change_type;
  unsigned int actual_id = 0;
  unsigned int cont, cont1, cont2;
  int ret = TRUE;

/* Reseteo todos los basic blocks */
  for ( cont = 0 ; cont < funcion1 -> cantidad_basic_blocks ; cont ++ )
  {
  /* Levanto el siguiente basic block */
    basic_block1 = funcion1 -> basic_blocks [ cont ];

  /* Reseteo las properties que me interesan */
    basic_block1 -> visitado = FALSE;
    basic_block1 -> association_id = -1;
    basic_block1 -> change_type = -1;
  }

/* Reseteo todos los basic blocks */
  for ( cont = 0 ; cont < funcion2 -> cantidad_basic_blocks ; cont ++ )
  {
  /* Levanto el siguiente basic block */
    basic_block2 = funcion2 -> basic_blocks [ cont ];

  /* Reseteo las properties que me interesan */
    basic_block2 -> visitado = FALSE;
    basic_block2 -> association_id = -1;
    basic_block2 -> change_type = -1;
  }

/* Levanto el basic block raiz de cada funcion */
  basic_block1 = funcion1 -> basic_blocks [ 0 ];
  basic_block2 = funcion2 -> basic_blocks [ 0 ];

/* Recorro el grafo asociando basic blocks desde el basic block raiz */
  diffear_funcion_recorriendo_grafo ( funcion1 , funcion2 , basic_block1 , basic_block2 , &actual_id );

/////////////////////////////////////////

/* Recorro todos los basic blocks de funcion1 */
  for ( cont1 = 0 ; cont1 < funcion1 -> cantidad_basic_blocks ; cont1 ++ )
  {
  /* Levanto el siguiente basic block */
    basic_block1 = funcion1 -> basic_blocks [ cont1 ];

  /* Si el basic block ya tiene ID */
    if ( basic_block1 -> association_id != -1 )
    {
    /* Sigo buscando */
      continue;
    }

  /* Recorro todos los basic blocks de funcion1 */
    for ( cont2 = 0 ; cont2 < funcion2 -> cantidad_basic_blocks ; cont2 ++ )
    {
    /* Levanto el siguiente basic block */
      basic_block2 = funcion2 -> basic_blocks [ cont2 ];

    /* Si el basic block ya tiene ID */
      if ( basic_block2 -> association_id != -1 )
      {
      /* Sigo buscando */
        continue;
      }

    /* Si los basic blocks tienen el mismo checksum */
      if ( basic_block1 -> checksum == basic_block2 -> checksum )
      {
      /* Si los basic blocks tienen la misma cantidad de instrucciones */
        if ( basic_block1 -> longitud == basic_block2 -> longitud )
        {
        /* Si los basic blocks tienen la misma cantidad de bytes */
          if ( basic_block1 -> longitud_en_bytes == basic_block2 -> longitud_en_bytes )
          {
          /* Si las probabilidades son buenas */
            if ( get_porcentaje_equivalencia ( 1 , 0 , funcion1 , funcion2 , basic_block1 , basic_block2 ) >= 50 )
            {
            /* Recorro el grafo asociando basic blocks desde el basic block raiz */
              diffear_funcion_recorriendo_grafo ( funcion1 , funcion2 , basic_block1 , basic_block2 , &actual_id );
            }
          }
        }
      }
    }
  }

/////////////////////////////////////////

/* Levanto el basic block raiz de cada funcion */
  basic_block1 = funcion1 -> basic_blocks [ 0 ];
  basic_block2 = funcion2 -> basic_blocks [ 0 ];

/* Por las dudas, chequeo los basic blocks raices */
  if ( ( basic_block1 -> association_id == -1 ) && ( basic_block2 -> association_id == -1 ) )
  {
  /* Si la probabilidad es buena */
    if ( get_porcentaje_equivalencia ( 1 , 0 , funcion1 , funcion2 , basic_block1 , basic_block2 ) > 50 )
    {
    /* Averiguo el tipo de cambio en el basic block */
      change_type = get_change_type ( basic_block1 , basic_block2 );

    /* Asocio los basic blocks ( los pinto de amarillo ) */
      basic_block1 -> association_id = actual_id;
      basic_block1 -> change_type = change_type;
      basic_block2 -> association_id = actual_id;
      basic_block2 -> change_type = change_type;
  
    /* Incremento el ID actual */
      actual_id ++;
    }
  }

/////////////////////////////////////////

/* Recorro el grafo hacia abajo asociando con la ayuda de IDs */
  diffear_funcion_usando_ids ( funcion1 , funcion2 , &actual_id );

/////////////////////////////////////////

/* Intento matchear libremente basic blocks por la mejor probabilidad */
  diffear_funcion_por_mejor_probabilidad ( funcion1 , funcion2 , &actual_id );

  return ( ret );
}

/****************************************************************************/

int diffear_funcion_recorriendo_grafo ( Funcion *funcion1 , Funcion *funcion2 , Basic_Block *basic_block1 , Basic_Block *basic_block2 , unsigned int *actual_id )
{
  List basic_blocks_padres1;
  List basic_blocks_padres2;
  Basic_Block *basic_block_padre1;
  Basic_Block *basic_block_padre2;
  Basic_Block *basic_block_hijo1;
  Basic_Block *basic_block_hijo2;
  unsigned int address_hija1;
  unsigned int address_hija2;
  unsigned int cont, cont1, cont2;
  unsigned int change_type;
  int asociacion_ok = FALSE;
  int ret = TRUE;

/* Si los basic blocks tienen la misma cantidad de salidas */
  if ( basic_block1 -> basic_blocks_hijos -> Len () == basic_block2 -> basic_blocks_hijos -> Len () )
  {
  /* Si los basic blocks tienen la misma longitud en instrucciones */
    if ( basic_block1 -> longitud == basic_block2 -> longitud )
    {
    /* Si los basic blocks tienen la misma longitud en bytes */
      if ( basic_block1 -> longitud_en_bytes == basic_block2 -> longitud_en_bytes )
      {
      /* Si los basic blocks tienen el mismo checksum */
        if ( basic_block1 -> checksum == basic_block2 -> checksum )
        {
        /* Asocio los basic blocks ( los pinto de blanco ) */
          basic_block1 -> association_id = *actual_id;
          basic_block1 -> change_type = 0;
          basic_block2 -> association_id = *actual_id;
          basic_block2 -> change_type = 0;

        /* Incremento el ID actual */
          ( *actual_id ) ++;

        /* Marco el flag de que los pude asociar */
          asociacion_ok = TRUE;
        }
      /* Si los basic blocks NO tienen el mismo checksum */
        else
        {
        /* Asocio los basic blocks ( los pinto de verde ) */
          basic_block1 -> association_id = *actual_id;
          basic_block1 -> change_type = 1;
          basic_block2 -> association_id = *actual_id;
          basic_block2 -> change_type = 1;
  
        /* Incremento el ID actual */
          ( *actual_id ) ++;

        /* Marco el flag de que los pude asociar */
          asociacion_ok = TRUE;
        }
      }
    }
  /* Si es un camino confiable */
    else if ( is_camino_confiable ( 1 , 0 , funcion1 , funcion2 , basic_block1 , basic_block2 ) == TRUE )
    {
    /* Averiguo el tipo de cambio en el basic block */
      change_type = get_change_type ( basic_block1 , basic_block2 );

    /* Asocio los basic blocks ( los pinto de amarillo ) */
      basic_block1 -> association_id = *actual_id;
      basic_block1 -> change_type = change_type;
      basic_block2 -> association_id = *actual_id;
      basic_block2 -> change_type = change_type;
  
    /* Incremento el ID actual */
      ( *actual_id ) ++;

    /* Marco el flag de que los pude asociar */
      asociacion_ok = TRUE;
    }
  }

/* Si NO los pude asociar */
  if ( asociacion_ok == FALSE )
  {
  /* Dejo de avanzar por este camino */
    return ( FALSE );
  }

/* Marco los basic blocks como visitados */
  basic_block1 -> visitado = TRUE;
  basic_block2 -> visitado = TRUE;

/* Si los basic blocks tienen dintinta cantidad de basic blocks hijos */
  if ( basic_block1 -> basic_blocks_hijos -> Len () != basic_block2 -> basic_blocks_hijos -> Len () )
  {
  /* Este camino deja de ser confiable */
    return ( FALSE );
  }

///////////////////////////////////////////

/* Recorro el grafo hacia abajo */

/* Recorro todos los basic blocks hijos del basic block donde estoy parado */
  for ( cont = 0 ; cont < basic_block1 -> basic_blocks_hijos -> Len () ; cont ++ )
  {
  /* Levanto las direcciones de los proximos basic blocks hijos */
    address_hija1 = ( unsigned int ) basic_block1 -> basic_blocks_hijos -> Get ( cont );
    address_hija2 = ( unsigned int ) basic_block2 -> basic_blocks_hijos -> Get ( cont );

  /* Levanto los basic blocks hijos */
    basic_block_hijo1 = get_basic_block_from_array ( funcion1 -> basic_blocks , funcion1 -> cantidad_basic_blocks , address_hija1 );
    basic_block_hijo2 = get_basic_block_from_array ( funcion2 -> basic_blocks , funcion2 -> cantidad_basic_blocks , address_hija2 );

  /* Si los basic blocks NO fueron visitados */
    if ( ( basic_block_hijo1 -> visitado == FALSE ) && ( basic_block_hijo2 -> visitado == FALSE ) )
    {
    /* Avanzo por este camino */
      diffear_funcion_recorriendo_grafo ( funcion1 , funcion2 , basic_block_hijo1 , basic_block_hijo2 , actual_id );
    }
  }

///////////////////////////////////////////

/* Recorro el grafo hacia arriba */

/* Obtengo todos los basic blocks padres de este */
  get_basic_blocks_padres ( funcion1 , basic_block1 , basic_blocks_padres1 );
  get_basic_blocks_padres ( funcion2 , basic_block2 , basic_blocks_padres2 );

/* Intento avanzar hacia arriba por el camino de los identicos */
  for ( cont1 = 0 ; cont1 < basic_blocks_padres1.Len () ; cont1 ++ )
  {
  /* Levanto el siguiente basic block padre */
    basic_block_padre1 = ( Basic_Block * ) basic_blocks_padres1.Get ( cont1 );

  /* Recorro todos los basic blocks padres de 2 */
    for ( cont2 = 0 ; cont2 < basic_blocks_padres2.Len () ; cont2 ++ )
    {
    /* Levanto el siguiente basic block padre */
      basic_block_padre2 = ( Basic_Block * ) basic_blocks_padres2.Get ( cont2 );

    /* Si los 2 basic blocks tienen el mismo checksum */
      if ( basic_block_padre1 -> checksum == basic_block_padre2 -> checksum )
      {
      /* Si los basic blocks NO fueron visitados */
        if ( ( basic_block_padre1 -> visitado == FALSE ) && ( basic_block_padre2 -> visitado == FALSE ) )
        {
        /* Intento asociar estos basic blocks */
//          diffear_funcion_recorriendo_grafo ( funcion1 , funcion2 , basic_block_padre1 , basic_block_padre2 , actual_id );
        }
      }
    }
  }

///////////////////////////////////////////

/* Intento avanzar hacia arriba por el camino de los basic blocks verdes */
  for ( cont1 = 0 ; cont1 < basic_blocks_padres1.Len () ; cont1 ++ )
  {
  /* Levanto el siguiente basic block padre */
    basic_block_padre1 = ( Basic_Block * ) basic_blocks_padres1.Get ( cont1 );

  /* Recorro todos los basic blocks padres de 2 */
    for ( cont2 = 0 ; cont2 < basic_blocks_padres2.Len () ; cont2 ++ )
    {
    /* Levanto el siguiente basic block padre */
      basic_block_padre2 = ( Basic_Block * ) basic_blocks_padres2.Get ( cont2 );

    /* Si los 2 basic blocks tienen el mismo checksum */
      if ( basic_block_padre1 -> longitud_en_bytes == basic_block_padre2 -> longitud_en_bytes )
      {
      /* Si los basic blocks NO fueron visitados */
        if ( ( basic_block_padre1 -> visitado == FALSE ) && ( basic_block_padre2 -> visitado == FALSE ) )
        {
        /* Intento asociar estos basic blocks */
          diffear_funcion_recorriendo_grafo ( funcion1 , funcion2 , basic_block_padre1 , basic_block_padre2 , actual_id );
        }
      }
    }
  }

  return ( ret );
}

/****************************************************************************/

int diffear_funcion_usando_ids ( Funcion *funcion1 , Funcion *funcion2 , unsigned int *actual_id )
{
  Basic_Block *basic_block1;
  Basic_Block *basic_block2;
  Basic_Block *basic_block_hijo1;
  Basic_Block *basic_block_hijo2;
  unsigned int address_hija1;
  unsigned int address_hija2;
  int cont1, cont2;
  unsigned int resultado1;
  unsigned int resultado2;
  unsigned int change_type;
  int ret = TRUE;

/* Recorro todos los basic blocks buscando los que estan asociados */
  for ( cont1 = 0 ; cont1 < funcion1 -> cantidad_basic_blocks ; cont1 ++ )
  {
  /* Levanto el siguiente basic block */
    basic_block1 = funcion1 -> basic_blocks [ cont1 ];

  /* Si el basic block NO tiene ID sigo buscando */
    if ( basic_block1 -> association_id == -1 )
    {
    /* Sigo buscando */
      continue;
    }

  /* Obtengo el basic block PAR */
    basic_block2 = get_basic_block_by_association_id ( funcion2 , basic_block1 -> association_id );

  /* Si tienen la misma cantidad de basic blocks hijos */
    if ( basic_block1 -> basic_blocks_hijos -> Len () == basic_block2 -> basic_blocks_hijos -> Len () )
    {
    /* Recorro todos los basic block hijos */
      for ( cont2 = 0 ; cont2 < basic_block1 -> basic_blocks_hijos -> Len () ; cont2 ++ )
      {
      /* Levanto las direcciones hijas */
        address_hija1 = ( unsigned int ) basic_block1 -> basic_blocks_hijos -> Get ( cont2 );
        address_hija2 = ( unsigned int ) basic_block2 -> basic_blocks_hijos -> Get ( cont2 );

      /* Levanto los basic blocks hijos */
        basic_block_hijo1 = get_basic_block_from_array ( funcion1 -> basic_blocks , funcion1 -> cantidad_basic_blocks , address_hija1 );
        basic_block_hijo2 = get_basic_block_from_array ( funcion2 -> basic_blocks , funcion2 -> cantidad_basic_blocks , address_hija2 );

      /* Si los basic blocks NO fueron asociados */
        if ( ( basic_block_hijo1 -> association_id == -1 ) && ( basic_block_hijo2 -> association_id == -1 ) )
        {
        /* Avanzo un nivel en el grafo */
          resultado1 = get_porcentaje_equivalencia ( 1 , 0 , funcion1 , funcion2 , basic_block_hijo1 , basic_block_hijo2 );

        /* Avanzo dos niveles en el grafo */
          resultado2 = get_porcentaje_equivalencia ( 2 , 0 , funcion1 , funcion2 , basic_block_hijo1 , basic_block_hijo2 );

        /* Si el resultado2 me da mejor o igual resultado que 1 */
          if ( ( resultado1 <= resultado2 ) && ( resultado2 >= 50 ) )
          {
          /* Averiguo el tipo de cambio en el basic block */
            change_type = get_change_type ( basic_block_hijo1 , basic_block_hijo2 );

          /* Asocio los basic blocks ( los pinto de amarillo ) */
            basic_block_hijo1 -> association_id = *actual_id;
            basic_block_hijo1 -> change_type = change_type;
            basic_block_hijo2 -> association_id = *actual_id;
            basic_block_hijo2 -> change_type = change_type;

          /* Incremento el ID actual */
            ( *actual_id ) ++;

          /* Reinicio la busqueda */
            cont1 = -1;

          /* Sigo buscando */
            break;
          }
        }
      }
    }
  }

  return ( ret );
}

/****************************************************************************/

int diffear_funcion_por_mejor_probabilidad ( Funcion *funcion1 , Funcion *funcion2 , unsigned int *actual_id )
{
  Basic_Block *basic_block1;
  Basic_Block *basic_block2;
  Basic_Block *basic_block_candidato;
  unsigned int mejor_probabilidad;
  unsigned int repeticiones;
  unsigned int probabilidad;
  unsigned int change_type;
  int cont1, cont2;
  int ret = TRUE;

/* Recorro todos los basic blocks de funcion1 */
  for ( cont1 = 0 ; cont1 < ( int ) funcion1 -> cantidad_basic_blocks ; cont1 ++ )
  {
  /* Levanto el siguiente basic block */
    basic_block1 = funcion1 -> basic_blocks [ cont1 ];

  /* Si el basic block ya tiene ID */
    if ( basic_block1 -> association_id != -1 )
    {
    /* Sigo buscando */
      continue;
    }

  /* Inicializo las variables */
    basic_block_candidato = NULL;
    mejor_probabilidad = 0;
    repeticiones = 0;

  /* Recorro todos los basic blocks de funcion2 */
    for ( cont2 = 0 ; cont2 < ( int ) funcion2 -> cantidad_basic_blocks ; cont2 ++ )
    {
    /* Levanto el siguiente basic block */
      basic_block2 = funcion2 -> basic_blocks [ cont2 ];

    /* Si el basic block ya tiene ID */
      if ( basic_block2 -> association_id != -1 )
      {
      /* Sigo buscando */
        continue;
      }

    /* Obtengo la probabilidad */
      probabilidad = get_porcentaje_equivalencia ( 1 , 0 , funcion1 , funcion2 , basic_block1 , basic_block2 );

    /* Si la probabilidad que tengo es mejor que la anterior */
      if ( probabilidad > mejor_probabilidad )
      {
      /* Tengo un nuevo candidato */
        basic_block_candidato = basic_block2;

      /* Seteo la nueva probabilidad */
        mejor_probabilidad = probabilidad;

      /* Seteo la cantidad de veces que esta probabilidad se repite */
        repeticiones = 1;
      }
    /* Si la probabilidad que tengo es igual a la anterior */
      else if ( probabilidad == mejor_probabilidad )
      {
      /* Incremento la cantidad de veces que esta probabilidad se repite */
        repeticiones ++;
      }
    }

  /* Si encontre algun basic block */
    if ( basic_block_candidato != NULL )
    {
    /* Si la probabilidad es buena */
      if ( mejor_probabilidad > 50 )
      {
      /* Si solo hubo una sola probabilidad con este valor */
        if ( repeticiones == 1 )
        {
        /* Averiguo el tipo de cambio en el basic block */
          change_type = get_change_type ( basic_block1 , basic_block_candidato );

        /* Asocio los basic blocks ( los pinto de amarillo ) */
          basic_block1 -> association_id = *actual_id;
          basic_block1 -> change_type = change_type;
          basic_block_candidato -> association_id = *actual_id;
          basic_block_candidato -> change_type = change_type;

        /* Incremento el ID actual */
          ( *actual_id ) ++;

        /* Empiezo a procesar desde el primer basic block de funcion1 */
          cont1 = -1;
        }
      }
    }
  }

  return ( ret );
}

/****************************************************************************/

unsigned int get_porcentaje_equivalencia ( unsigned int maxima_profundidad , unsigned int profundidad , Funcion *funcion1 , Funcion *funcion2 , Basic_Block *basic_block1 , Basic_Block *basic_block2 )
{
  unsigned int caminos_correctos;
  unsigned int caminos_inciertos;
  unsigned int caminos_erroneos;
  unsigned int topes_encontrados;
  unsigned int resultado;

/* Inicializo las variables estadisticas */
  caminos_correctos = 0;
  caminos_inciertos = 0;
  caminos_erroneos = 0;

/* Averiguo el porcentaje de equivalencia */
  recorrer_camino_de_equivalencia ( maxima_profundidad , profundidad , funcion1 , funcion2 , basic_block1 , basic_block2 , &caminos_correctos , &caminos_inciertos , &caminos_erroneos );

/* Calculo la cantidad de veces que tuve que retroceder */
  topes_encontrados = caminos_correctos + caminos_inciertos + caminos_erroneos;

/* Si NO me da cero */
  if ( topes_encontrados > 0 )
  {
  /* Calculo el porcentaje */
    resultado = ( caminos_correctos * 100 ) / topes_encontrados;
    resultado += ( ( caminos_inciertos * 100 ) / 2 ) / topes_encontrados;
  }

  return ( resultado );
}

/****************************************************************************/

int recorrer_camino_de_equivalencia ( unsigned int maxima_profundidad , unsigned int profundidad , Funcion *funcion1 , Funcion *funcion2 , Basic_Block *basic_block1 , Basic_Block *basic_block2 , unsigned int *caminos_correctos , unsigned int *caminos_inciertos , unsigned int *caminos_erroneos )
{
  Basic_Block *basic_block_hijo1;
  Basic_Block *basic_block_hijo2;
  unsigned int address_hija1;
  unsigned int address_hija2;
  unsigned int cont;
  int ret = TRUE;

/* Si los basic blocks estan identificados */
  if ( ( basic_block1 -> association_id != -1 ) && ( basic_block1 -> association_id == basic_block2 -> association_id ) )
  {
  /* Incremento la cantidad de caminos correctos */
    ( *caminos_correctos ) ++;

  /* Dejo de avanzar por este camino */
    return ( ret );
  }
/* Si hay una CONDICION INVERTIDA */
  else if ( is_reverted_condition ( funcion1 , funcion2 , basic_block1 , basic_block2 ) == TRUE )
  {
  /* Incremento la cantidad de caminos correctos */
    ( *caminos_correctos ) ++;

  /* Dejo de avanzar por este camino */
    return ( ret );
  }
/* Si los basic blocks tienen distinto ID */
  else if ( basic_block1 -> association_id != basic_block2 -> association_id )
  {
  /* Incremento la cantidad de caminos que me llevan a basic blocks con distintos IDs */
    ( *caminos_erroneos ) ++;

  /* Dejo de avanzar por este camino */
    return ( ret );
  }
/* Si los basic blocks tienen distinta cantidad de basic blocks hijos */
  else if ( basic_block1 -> basic_blocks_hijos -> Len () != basic_block2 -> basic_blocks_hijos -> Len () )
  {
  /* Incremento la cantidad de caminos que me llevan a basic blocks con distintos IDs */
    ( *caminos_erroneos ) ++;

  /* Dejo de avanzar por este camino */
    return ( ret );
  }
/* Si llegue a la maxima profundidad sin encontrar basic blocks identificados */
  else if ( profundidad == maxima_profundidad )
  {
  /* Incremento la cantidad de caminos que no se a donde llevan */
    ( *caminos_inciertos ) ++;

  /* Dejo de avanzar por este camino */
    return ( ret );
  }

/* Recorro todos los basic block hijos de este */
  for ( cont = 0 ; cont < basic_block1 -> basic_blocks_hijos -> Len () ; cont ++ )
  {
  /* Levanto las direcciones hijas */
    address_hija1 = ( unsigned int ) basic_block1 -> basic_blocks_hijos -> Get ( cont );
    address_hija2 = ( unsigned int ) basic_block2 -> basic_blocks_hijos -> Get ( cont );

  /* Levanto los basic blocks hijos */
    basic_block_hijo1 = get_basic_block_from_array ( funcion1 -> basic_blocks , funcion1 -> cantidad_basic_blocks , address_hija1 );
    basic_block_hijo2 = get_basic_block_from_array ( funcion2 -> basic_blocks , funcion2 -> cantidad_basic_blocks , address_hija2 );

  /* Avanzo por este camino */
    recorrer_camino_de_equivalencia ( maxima_profundidad , profundidad + 1 , funcion1 , funcion2 , basic_block_hijo1 , basic_block_hijo2 , caminos_correctos , caminos_inciertos , caminos_erroneos );
  }

  return ( ret );
}

/****************************************************************************/

int is_reverted_condition ( Funcion *funcion1 , Funcion *funcion2 , Basic_Block *basic_block1 , Basic_Block *basic_block2 )
{
  Basic_Block *basic_block_hijo11;
  Basic_Block *basic_block_hijo12;
  Basic_Block *basic_block_hijo21;
  Basic_Block *basic_block_hijo22;
  unsigned int address_hija11;
  unsigned int address_hija12;
  unsigned int address_hija21;
  unsigned int address_hija22;
  int ret = FALSE;

/* Si los basic blocks tienen 2 salidas */
  if ( ( basic_block1 -> basic_blocks_hijos -> Len () == 2 ) && ( basic_block2 -> basic_blocks_hijos -> Len () == 2 ) )
  {
  /* Obtengo las direcciones de los basic blocks hijos */
    address_hija11 = ( unsigned int ) basic_block1 -> basic_blocks_hijos -> Get ( 0 );
    address_hija12 = ( unsigned int ) basic_block1 -> basic_blocks_hijos -> Get ( 1 );
    address_hija21 = ( unsigned int ) basic_block2 -> basic_blocks_hijos -> Get ( 0 );
    address_hija22 = ( unsigned int ) basic_block2 -> basic_blocks_hijos -> Get ( 1 );

  /* Obtengo los basic blocks hijos cruzados */
    basic_block_hijo11 = get_basic_block_from_array ( funcion1 -> basic_blocks , funcion1 -> cantidad_basic_blocks , address_hija11 );
    basic_block_hijo12 = get_basic_block_from_array ( funcion1 -> basic_blocks , funcion1 -> cantidad_basic_blocks , address_hija12 );
    basic_block_hijo21 = get_basic_block_from_array ( funcion2 -> basic_blocks , funcion2 -> cantidad_basic_blocks , address_hija21 );
    basic_block_hijo22 = get_basic_block_from_array ( funcion2 -> basic_blocks , funcion2 -> cantidad_basic_blocks , address_hija22 );

  /* Si todos los basic blocks fueron asociados */
    if ( ( basic_block_hijo11 -> association_id != -1 ) && ( basic_block_hijo12 -> association_id != -1 ) && ( basic_block_hijo21 -> association_id != -1 ) && ( basic_block_hijo22 -> association_id != -1 ) )
    {
    /* Si detecto el primer cruce */
      if ( basic_block_hijo11 -> association_id == basic_block_hijo22 -> association_id )
      {
      /* Si detecto el segundo cruce */
        if ( basic_block_hijo12 -> association_id == basic_block_hijo21 -> association_id )
        {
        /* Condicion invertida detectada */
          ret = TRUE;
        }
      }
    }
  }

  return ( ret );
}

/****************************************************************************/

unsigned int get_change_type ( Basic_Block *basic_block1 , Basic_Block *basic_block2 )
{
  unsigned int change_type;

/* Si tienen el checksum IDENTICO */
  if ( basic_block1 -> checksum == basic_block2 -> checksum )
  {
  /* Pinto el basic block de BLANCO */
    change_type = 0;
  }
/* Si tienen la misma cantidad de instrucciones */
  else if ( basic_block1 -> longitud == basic_block2 -> longitud )
  {
  /* Pinto el basic block de VERDE */
    change_type = 1;
  }
  else
  {
  /* Pinto el basic block de AMARILLO */
    change_type = 2;
  }

  return ( change_type );
}

/****************************************************************************/

int armar_grafo_salida ( char *file , char *output_file , char *disasm_file , Funcion *funcion )
{
  Basic_Block *basic_block;
  String desensamblado;
  char basic_block_content [ MAX_DISASM ];
  char basic_block_label [ 256 ];
  char vertical_order [ 64 ];
  char name [ NAME_LEN ];
  unsigned int cont;
  unsigned int cont2;
  int ret = TRUE;
  FILE *fout;
  FILE *fdis;

/* Reseteo la profundidad de todos los basic blocks */
  for ( cont = 0 ; cont < funcion -> cantidad_basic_blocks ; cont ++ )
  {
  /* Levanto el siguiente basic block */
    basic_block = funcion -> basic_blocks [ cont ]; 

  /* Seteo la MINIMA profundidad del basic block */
    basic_block -> profundidad = -1;
  }

/* Seteo la profundidad de los basic blocks */
  setear_maxima_profundidad_hacia_abajo ( 0 , funcion , funcion -> basic_blocks [ 0 ] );

/* Creo el archivo donde voy a guardar el grafo */
  fout = qfopen ( output_file , "w" );

/* Obtengo el nombre de la funcion */
  get_formated_name ( funcion , name , NAME_LEN , FALSE );

/* Genero la salida para graficar el grafo */
  qfprintf ( fout , "graph:\n" );
  qfprintf ( fout , "{\n" );
  qfprintf ( fout , "title: \"%s - %s\"\n" , file , name );
  qfprintf ( fout , "manhattan_edges: yes\n" );
  qfprintf ( fout , "layoutalgorithm: mindepth\n" );
  qfprintf ( fout , "finetuning: no\n" );
  qfprintf ( fout , "layout_downfactor: 100\n" );
  qfprintf ( fout , "layout_upfactor: 0\n" );
  qfprintf ( fout , "layout_nearfactor: 10\n" );
  qfprintf ( fout , "xlspace: 12\n" );
  qfprintf ( fout , "yspace: 30\n" );
  qfprintf ( fout , "\n" );

/* Abro el archivo con el desensamblado */
  fdis = qfopen ( disasm_file , "rb" );

/* Escribo todos los basic blocks como nodos */
  for ( cont = 0 ; cont < funcion -> cantidad_basic_blocks ; cont ++ )
  {
  /* Levanto el siguiente basic block */
    basic_block = funcion -> basic_blocks [ cont ];

  /* Transformo la direccion del basic block en una etiqueta */
//    qsnprintf ( basic_block_label , 256 , "%x:%u-%u:%u:%i" , basic_block -> addr_inicial , basic_block -> profundidad , basic_block -> profundidad2 , basic_block -> peso , basic_block -> id );
    qsnprintf ( basic_block_label , 256 , "%x: chk=%x" , basic_block -> addr_inicial , basic_block -> checksum );
//    qsnprintf ( basic_block_label , 256 , "%x" , basic_block -> addr_inicial );

  /* Me posiciono en la direccion del file que indica el basic block */
    qfseek ( fdis , basic_block -> pos_file_disasm , SEEK_SET );

  /* Reinicializo el objeto string */
    desensamblado.Reset ();

  /* Levanto las instrucciones del basic block */
    desensamblado.Load ( fdis );

  /* Saco el ultimo fin de linea de la ultima instruccion */
    desensamblado.Truncate ( desensamblado.Len () - 1 );

  /* Seteo el orden vertical donde se va a ubicar el basic block */
    qsnprintf ( vertical_order , 64 , "vertical_order: %i " , basic_block -> profundidad );

  /* Si el basic block NO pudo ser asociado, significa que cambio mucho */
    if ( basic_block -> association_id == -1 )
    {
    /* direccion + instrucciones */
      qsnprintf ( basic_block_content , MAX_DISASM , "%s\n\n%s" , basic_block_label , desensamblado.Get () );

    /* Declaro el nodo en el grafo */
      qfprintf ( fout , "node: { title: \"%x\" label: \"%s\" color: red textcolor: black bordercolor: black %s" , basic_block -> addr_inicial , basic_block_content , vertical_order );
    }
  /* Si el basic block tuvo cambios en la longitud */
    else if ( basic_block -> change_type == 2 )
    {
    /* ID + direccion + instrucciones */
      qsnprintf ( basic_block_content , MAX_DISASM , "ID_%i\n%s\n\n%s" , basic_block -> association_id , basic_block_label , desensamblado.Get () );

    /* Declaro el nodo en el grafo */
      qfprintf ( fout , "node: { title: \"%x\" label: \"%s\" color: %s textcolor: black bordercolor: black %s" , basic_block -> addr_inicial , basic_block_content , "yellow" , vertical_order );
    }
  /* Si el basic block no cambio o tuvo cambios triviales */
    else
    {
    /* ID + direccion + instrucciones */
      qsnprintf ( basic_block_content , MAX_DISASM , "ID_%i\n%s\n\n%s" , basic_block -> association_id , basic_block_label , desensamblado.Get () );

    /* Declaro el nodo en el grafo */
      qfprintf ( fout , "node: { title: \"%x\" label: \"%s\" color: %s textcolor: black bordercolor: black %s" , basic_block -> addr_inicial , basic_block_content , ( basic_block -> change_type == 0 ) ? "white":"green" , vertical_order );
    }

  /* Cierro el basic block */
    qfprintf ( fout , "}\n" );
  }

/* Dejo un espacio en blanco */
  qfprintf ( fout , "\n" );

/* Escribo todas las conexiones entre los nodos */
  for ( cont = 0 ; cont < funcion -> cantidad_basic_blocks ; cont ++ )
  {
  /* Levanto el siguiente basic block */
    basic_block = funcion -> basic_blocks [ cont ];

  /* Si el basic block tiene 2 salidas ( TRUE - FALSE ) */
    if ( basic_block -> basic_blocks_hijos -> Len () == 2 )
    {
    /* Declaro el enlace POSITIVO en el grafo */
      qfprintf ( fout , "edge: { sourcename: \"%x\" targetname: \"%x\" color: green }\n" , basic_block -> addr_inicial , ( unsigned int ) basic_block -> basic_blocks_hijos -> Get ( 0 ) );

    /* Declaro el enlace NEGATIVO en el grafo */
      qfprintf ( fout , "edge: { sourcename: \"%x\" targetname: \"%x\" color: red }\n" , basic_block -> addr_inicial , ( unsigned int ) basic_block -> basic_blocks_hijos -> Get ( 1 ) );
    }
  /* Si tiene cero, uno o mas de 2 basic blocks hijos */
    else
    {
    /* Recorro todas las conexiones hacia otros basic blocks hijos */
      for ( cont2 = 0 ; cont2 < basic_block -> basic_blocks_hijos -> Len () ; cont2 ++ )
      {
      /* Declaro el enlace en el grafo */
        qfprintf ( fout , "edge: { sourcename: \"%x\" targetname: \"%x\" color: blue }\n" , basic_block -> addr_inicial , ( unsigned int ) basic_block -> basic_blocks_hijos -> Get ( cont2 ) );
      }
    }
  }

/* Fin del grafo */
  qfprintf ( fout , "}\n" );

/* Cierro el file */
  qfclose ( fout );

/* Cierro el file de desensamblado */
  qfclose ( fdis );

  return ( ret );
}

/****************************************************************************/

void mostrar_grafo ( char *output_file )
{
  char ida_path [ MAX_PATH ];
  char wingraph_line [ MAX_PATH * 2 ];
  char *pathname;

/* Averiguo la ruta del IDA */
  GetModuleFileName ( GetModuleHandle ( NULL ) , ida_path , MAX_PATH );

/* Busco la ultima barra */
  pathname = strrchr ( ida_path , '\\' );

/* Si encontro la ultima barra */
  if ( pathname != NULL )
  {
  /* Reemplazo 'idag.exe' por 'wingraph.exe' */
    qsnprintf ( pathname , MAX_PATH - strlen ( ida_path ) , "\\%s" , "wingraph32.exe -remove" );

  /* Armo el path completo para pasarle al graficador de IDA */
    qsnprintf ( wingraph_line , MAX_PATH * 2 , "%s %s" , ida_path , output_file );

  /* Muestro el grafo */
    WinExec ( wingraph_line , SW_SHOW );
  }
}

/****************************************************************************/

void mostrar_grafos ( char *grafo1 , char *grafo2 )
{
  String cmd;
  String *vpath;
  char cmd2 [ MAX_PATH ];
  char ida_path [ MAX_PATH ];
  char caracter [ 2 ];
  char *path;
  unsigned int cont;
  int mostrar_separados = FALSE;

/* Obtengo el path del viewer */
  vpath = ( String * ) viewer_paths.Get ( visualizador );
  path = ( char * ) vpath -> Get ();

/* Recorro caracter a caracter el path del viewer */
  for ( cont = 0 ; cont < vpath -> Len () ; cont ++ )
  {
  /* Si NO tengo un caracter $ */
    if ( path [ cont ] != '$' )
    {
    /* Hago una copia del caracter */
      qsnprintf ( caracter , 2 , "%c" , path [ cont ] );

    /* Agrego el caracter a la linea */
      cmd.Append ( caracter );
    }
  /* Si tengo una variable */
    else
    {
    /* Si tengo que reemplazarlo por el PATH de IDA */
      if ( path [ cont + 1 ] == '0' )
      {
      /* Obtengo el directorio donde esta IDA */
        get_ida_path ( MAX_PATH , ida_path );

      /* Agrego el PATH de IDA */
        cmd.Append ( ida_path );  

      /* Avanzo 1 espacio */
        cont ++;
      }
    /* Si tengo que reemplazarlo por el grafo 1 y el grafo 2 */
      else if ( ( path [ cont + 1 ] == '1' ) && ( path [ cont + 2 ] == '2' ) )
      {
      /* Armo un string generico */
        cmd.Append ( "\"" );
        cmd.Append ( "%s" );  
        cmd.Append ( "\"" );

      /* Prendo el flag */
        mostrar_separados = TRUE;

      /* Avanzo 2 espacios */
        cont = cont + 2;
      }
    /* Si tengo que reemplazarlo por el grafo 1 */
      else if ( path [ cont + 1 ] == '1' )
      {
      /* Agrego el nombre del grafo 1 */
        cmd.Append ( "\"" );
        cmd.Append ( grafo1 );
        cmd.Append ( "\"" );

      /* Avanzo 1 espacio */
        cont ++;
      }
    /* Si tengo que reemplazarlo por el grafo 2 */
      else if ( path [ cont + 1 ] == '2' )
      {
      /* Agrego el nombre del grafo 2 */
        cmd.Append ( "\"" );
        cmd.Append ( grafo2 );
        cmd.Append ( "\"" );

      /* Avanzo 1 espacio */
        cont ++;
      }
    /* Si tengo que reemplazarlo por el archivo de resultados */
      else if ( path [ cont + 1 ] == '3' )
      {
      /* Agrego el nombre del arhivo de resultados */
        cmd.Append ( "\"" );
        cmd.Append ( result_file );
        cmd.Append ( "\"" );

      /* Avanzo 1 espacio */
        cont ++;
      }
    }
  }

/* Si tengo que mostrar los grafos por separados */
  if ( mostrar_separados == TRUE )
  {
  /* Armo la linea de comandos para el grafo 1 */
    qsnprintf ( cmd2 , MAX_PATH , cmd.Get () , grafo1 );

  /* Muestro el grafo */
    WinExec ( cmd2 , SW_SHOW );

  /* Armo la linea de comandos para el grafo 2 */
    qsnprintf ( cmd2 , MAX_PATH , cmd.Get () , grafo2 );

  /* Muestro el grafo */
    WinExec ( cmd2 , SW_SHOW );
  }
  else
  {
  /* Muestro el grafo */
    WinExec ( cmd.Get () , SW_SHOW );
  }
}

/****************************************************************************/

int buscar_funciones_equivalentes ( char *file1 , char *file2 )
{
  List funciones_a_recorrer;
  Funcion *funcion1;
  Funcion *funcion2;
  unsigned int address1 = 0;
  unsigned int address2 = 0;
  unsigned int cont;
  unsigned int matcheds;
  int ret = TRUE;
  FILE *f1;
  FILE *f2;

/* Intento abrir los 2 files de relevamiento */
  f1 = qfopen ( file1 , "rb" );
  f2 = qfopen ( file2 , "rb" );

/* Si NO pude abrir alguno de los files */
  if ( f1 == NULL || f2 == NULL )
  {
  /* Mensaje de ERROR al usuario */
    my_msg ( "ERROR: analized files don't exist !\n" );

  /* Salgo */
    return ( FALSE );
  }

/* Mensaje al usuario */
  my_msg ( "loading analized files ...\n" );

/* Levanto los 2 archivos */
  levantar_funciones ( f1 , indice_funciones1 , funciones1 );
  levantar_funciones ( f2 , indice_funciones2 , funciones2 );

/* Mientras el usuario ingrese direcciones */
//  while ( my_askaddr ( ( unsigned long int * ) &address , "This option searchs an equivalent function in the second file" ) == TRUE )

  while ( my_AskUsingForm ( funciones_a_buscar , &address1 , &address2 ) == TRUE )
  {
  /* Si la direccion es del file1 */
    if ( address1 != 0 )
    {
    /* Lista de funciones a usar */
      funciones_a_recorrer = funciones2;

    /* Busco la funcion ingresada por el usuario */
      funcion1 = get_estructura_funcion2 ( indice_funciones1 , funciones1 , address1 );
    }
  /* Si la direccion es del file2 */
    else
    {
    /* Lista de funciones a usar */
      funciones_a_recorrer = funciones1;

    /* Busco la funcion ingresada por el usuario */
      funcion1 = get_estructura_funcion2 ( indice_funciones2 , funciones2 , address2 );
    }

  /* Si la direccion ingresada por el usuario NO existe */
    if ( funcion1 == NULL )
    {
    /* Mensaje de ERROR */
      my_msg ( "ERROR: the function doesn't exist\n" );

    /* Reinicializo las direcciones a buscar */
      address1 = 0;  
      address2 = 0;  

    /* Continuo pidiendo direcciones */
      continue;
    }

  /* Inicializo el contador de matcheos */
    matcheds = 0;

  /* Mensaje al usuario */
    my_msg ( "searching equivalent functions of %x\n" , funcion1 -> address );

  /* Recorro todas las funciones de programa2 */
    for ( cont = 0 ; cont < funciones_a_recorrer.Len () ; cont ++ )
    {
    /* Levanto la siguiente funcion */
      funcion2 = ( Funcion * ) funciones_a_recorrer.Get ( cont );

    /* Si las 2 funciones tienen la misma geometria */
      if ( strcmp ( funcion1 -> graph_ecuation , funcion2 -> graph_ecuation ) == 0 )
      {
      /* Imprimo la posible funcion equivalente */
        my_msg ( "equivalent matched: %x\n" , funcion2 -> address );

      /* Incremento el contador de matcheos */
        matcheds ++;
      }
    }

  /* Si NO encontre funciones equivalentes */
    if ( matcheds == 0 )
    {
    /* Mensaje al usuario */
      my_msg ( "equivalent function not found\n" );
    }
    else
    {
    /* Fin de la busqueda */
      my_msg ( "done\n" );
    }

  /* Reinicializo las direcciones a buscar */
    address1 = 0;  
    address2 = 0;  
  }

/* Cierro los 2 files */
  qfclose ( f1 );
  qfclose ( f2 );

  return ( ret );
}

/****************************************************************************/

void get_ida_path ( unsigned int len , char *path )
{
  char ida_path [ QMAXPATH ];
  char *pathname;

/* Averiguo la ruta del IDA */
  GetModuleFileName ( GetModuleHandle ( NULL ) , ida_path , QMAXPATH );

/* Busco la ultima barra */
  pathname = strrchr ( ida_path , '\\' );

/* Si encontro la ultima barra */
  if ( pathname != NULL )
  {
  /* Cierro el string */
    *pathname = 0;
  }

/* Retorno el string */
  qstrncpy ( path , ida_path , len );
}

/****************************************************************************/
/****************************************************************************/ 
//
//      PLUGIN DESCRIPTION BLOCK
//
/****************************************************************************/ 
/****************************************************************************/ 

__declspec ( dllexport ) plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_UNL,         // plugin flags
//  0,                    // plugin flags
  init,                 // initialize

  NULL,                 // terminate. this pointer may be NULL.

  run,                  // invoke plugin

  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  help,                 // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};

/****************************************************************************/
/****************************************************************************/ 

