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

/* list.cpp */

/****************************************************************************/
/****************************************************************************/

/* Prototipos */

class List
{
private:
  int ordenada;
  unsigned int len;
  void **elementos;

private:
  int Get_Element_By_Secuential_Search ( void * , unsigned int * );
  int Get_Element_By_Binary_Search ( void * , unsigned int * );

public:
  List ();
  ~List ();
  unsigned int Len ();
  unsigned int Add ( void * );
  void Append ( List * );
  void *Get ( unsigned int );
  int GetPos ( void * , unsigned int * );
  int Set ( unsigned int , void * );
  int Find ( void * );
  int Delete ( unsigned int );
  int DeleteElement ( void * );
  int Clear ( void );
  void Sort ( void );
  int Swap ( unsigned int , unsigned int );

/* Metodos para hacer PERSISTENCIA */
  int Save ( FILE * );
  int Load ( FILE * );
};

/****************************************************************************/
/****************************************************************************/

/* Prototipos de funciones */

int get_element_by_secuential_search ( void * , unsigned int * );
int get_element_by_binary_search ( void * , unsigned int * );

/****************************************************************************/
/****************************************************************************/

/* Defines */

#define FALSE 0
#define TRUE  1

/* Para mantener la compatibilidad */
#ifdef _IDA_HPP
  #define fread(a,b,c,d) qfread(d,a,b)
  #define fwrite(a,b,c,d) qfwrite(d,a,b)
#endif

/****************************************************************************/
/****************************************************************************/

/* Funciones */

List::List ()
{
/* Seteo el flag que indica que la lista esta ordenada */
  this -> ordenada = TRUE;

/* Seteo la longitud de la lista */
  this -> len = 0;

/* Inicializo la lista */
  this -> elementos = NULL;
}

/****************************************************************************/

List::~List ()
{
/* Libero la lista */
  free ( this -> elementos );
}

/****************************************************************************/

unsigned int List::Len ( void )
{
/* Retorno la longitud de la lista */
  return ( this -> len );
}

/****************************************************************************/

unsigned int List::Add ( void *elemento )
{
  void *new_list;
  unsigned int ultima_pos;

/* Agrando la lista */
  new_list = realloc ( this -> elementos , ( sizeof ( void * ) ) * ( this -> len + 1 ) ); 

/* Si pude agrandar la lista */
  if ( new_list != NULL )
  {
  /* Seteo la nueva lista */
    this -> elementos = ( void ** ) new_list;

  /* Agrego el nuevo elemento */
    this -> elementos [ this -> len ] = elemento;

  /* Agrando la longitud de la lista */
    this -> len ++;

  /* Retorno la posicion donde se agrego el elemento */
    ultima_pos = this -> len - 1;

  /* Si hay mas de 1 elemento en la lista */
    if ( this -> len > 1 )
    {
    /* Si el elemento agregado es menor al ultimo elemento */
      if ( this -> elementos [ this -> len - 2 ] > elemento )
      {
      /* Pierdo el orden en la lista */
        this -> ordenada = FALSE;
      }
    }
  }

  return ( ultima_pos );
}

/****************************************************************************/

void List::Append ( List *second_list )
{
  unsigned int pos;
  int ret = TRUE;

/* Recorro toda la lista */
  for ( pos = 0 ; pos < second_list -> Len () ; pos ++ )
  {
  /* Agrego el elemento a la lista */
    this -> Add ( second_list -> Get ( pos ) );
  }
}

/****************************************************************************/

void *List::Get ( unsigned int pos )
{
  void *elemento = NULL;

/* Si el elemento esta dentro de la lista */
  if ( pos < this -> len )
  {
  /* Retorno el elemento que hay en esa posicion */
    elemento = this -> elementos [ pos ];
  }

  return ( elemento );
}

/****************************************************************************/

int List::GetPos ( void *elemento , unsigned int *posicion )
{
  int ret;

/* Si la lista se conserva ordenada y tiene mas de 2 elementos */
  if ( ( this -> ordenada == TRUE ) && ( this -> Len () > 2 ) )
  {
  /* Busco el elemento en la lista en forma binaria */
    ret = this -> Get_Element_By_Binary_Search ( elemento , posicion );
  }
  else
  {
  /* Busco el elemento en la lista en forma secuencial */
    ret = this -> Get_Element_By_Secuential_Search ( elemento , posicion );
  }

  return ( ret );
}

/****************************************************************************/

int List::Set ( unsigned int posicion , void *elemento )
{
  int ret = TRUE;

/* Si la posicion NO sobrepasa el rango de elementos */
  if ( posicion < this -> Len () )
  {
  /* Piso el elemento existente */
    this -> elementos [ posicion ] = elemento;

  /* Apago el orden en la lista ( arreglar en algun momento ) */
    this -> ordenada = FALSE;
  }

  return ( ret );
}

/****************************************************************************/

int List::Find ( void *elemento )
{
  unsigned int pos;
  int ret;

/* Si la lista se conserva ordenada y tiene mas de 2 elementos */
  if ( ( this -> ordenada == TRUE ) && ( this -> Len () > 2 ) )
  {
  /* Busco el elemento en la lista en forma binaria */
    ret = this -> Get_Element_By_Binary_Search ( elemento , &pos );
  }
  else
  {
  /* Busco el elemento en la lista en forma secuencial */
    ret = this -> Get_Element_By_Secuential_Search ( elemento , &pos );
  }

  return ( ret );
}

/****************************************************************************/

int List::Delete ( unsigned int pos )
{
  unsigned int cont;
  int ret = FALSE;

/* Si el elemento esta dentro de la lista */
  if ( pos < this -> len )
  {
  /* Compacto la lista */
    for ( cont = ( pos + 1 ) ; cont < this -> len ; cont ++ )
    {
    /* Muevo el valor del actual al anterior */
      this -> elementos [ cont - 1 ] = this -> elementos [ cont ];
    }

  /* Achico la lista */
    this -> elementos = ( void ** ) realloc ( this -> elementos , ( sizeof ( void * ) ) * ( this -> len - 1 ) );

  /* Seteo la nueva longitud de la lista */
    this -> len --;

  /* Retorno OK */
    ret = TRUE;
  }

  return ( ret );
}

/****************************************************************************/

int List::DeleteElement ( void *elemento )
{
  unsigned int pos;
  int ret = FALSE;

/* Si el elemento existe */
  if ( this -> GetPos ( elemento , &pos ) == TRUE )
  {
  /* Elimino el elemento de la lista */
    this -> Delete ( pos );

  /* Retorno OK */
    ret = TRUE;
  }

  return ( ret );
}

/****************************************************************************/

int List::Clear ( void )
{
  int ret = TRUE;

/* Reinicializo el flag de lista ordenada */
  this -> ordenada = TRUE;

/* Seteo la longitud de la lista */
  this -> len = 0;

/* Libero la lista */
  free ( this -> elementos );

/* Inicializo la lista */
  this -> elementos = NULL;

  return ( ret );
}

/****************************************************************************/

void List::Sort ( void )
{
  unsigned int cont1;
  unsigned int cont2;
  void *elemento_temporal;

/* Si NO hay elementos para ordenar */
  if ( this -> Len () < 2 )
  {
  /* Salgo sin hacer nada */
    return;
  }

/* Recorro todos los elementos */
  for ( cont1 = 0 ; cont1 < this -> Len () - 1 ; cont1 ++ )
  {
  /* Recorro todos los elementos */
    for ( cont2 = cont1 + 1 ; cont2 < this -> Len () ; cont2 ++ )
    {
    /* Si elemento1 es mayor que elemento2 */
      if ( this -> elementos [ cont1 ] > this -> elementos [ cont2 ] )
      {
      /* Intercambio los elementos */
        elemento_temporal = this -> elementos [ cont1 ];
        this -> elementos [ cont1 ] = this -> elementos [ cont2 ];
        this -> elementos [ cont2 ] = elemento_temporal;
      }
    }
  }

/* Marco la lista como ordenada */
  this -> ordenada = TRUE;
}

/****************************************************************************/

int List::Swap ( unsigned int pos1 , unsigned int pos2 )
{
  void *elemento1;
  void *elemento2;
  int ret = FALSE;

/* Si los rangos NO estan fuera de la cantidad de elementos */
  if ( ( pos1 < this -> Len () ) && ( pos2 < this -> Len () ) )
  {
  /* Obtengo el primer elemento */
    elemento1 = this -> Get ( pos1 );

  /* Obtengo el segundo elemento */
    elemento2 = this -> Get ( pos2 );

  /* Seteo el lugar del primer elemento con el segundo */
    this -> Set ( pos1 , elemento2 );

  /* Seteo el lugar del segundo elemento con el primero */
    this -> Set ( pos2 , elemento1 );

  /* Retorno OK */
    ret = TRUE;
  }

  return ( ret );
}

/****************************************************************************/

int List::Get_Element_By_Secuential_Search ( void *elemento , unsigned int *pos )
{
  unsigned int cont;
  unsigned int len;
  int ret = FALSE;

/* Averiguo la longitud de la lista */
  len = this -> Len ();

/* Busco el elemento en la lista */
  for ( cont = 0 ; cont < len ; cont ++ )
  {
  /* Si es el elemento que estoy buscando */
    if ( this -> Get ( cont ) == elemento )
    {
    /* Retorno la posicion del elemento */
      *pos = cont;

    /* Retorno OK */
      ret = TRUE;

    /* Corto la busqueda */
      break;
    }
  }

  return ( ret );
}

/****************************************************************************/

int List::Get_Element_By_Binary_Search ( void *elemento , unsigned int *pos )
{
  unsigned int valor_actual;
  int cota_minima;
  int cota_maxima;
  int pos_actual;
  int ret = FALSE;

/* Seteo la posicion minima */
  cota_minima = 0;

/* Seteo la posicion maxima */
  cota_maxima = this -> Len () - 1;

/* Mientras no se junten la minima con la maxima */
  while ( cota_minima <= cota_maxima )
  {
  /* Me posiciono en la mitad de las 2 cotas */
    pos_actual = ( cota_minima + cota_maxima ) / 2;

  /* Leo el valor correspondiente a la posicion */
    valor_actual = ( unsigned int ) this -> elementos [ pos_actual ];

  /* Si es el valor que estaba buscando */
    if ( valor_actual == ( unsigned int ) elemento )
    {
    /* Retorno la posicion */
      *pos = pos_actual;

    /* Retorno OK */
      ret = TRUE;

    /* Corto la busqueda */
      break;
    }

  /* Si el valor actual es mas chico que el valor que estoy buscando */
    if ( valor_actual < ( unsigned int ) elemento )
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

int List::Save ( FILE *f )
{
  int ret = TRUE;

/* Guardo las propiedades del objeto */
  fwrite ( this , sizeof ( List ) , 1 , f );

/* Guardo la lista de todos los elementos */
  fwrite ( this -> elementos , this -> len * sizeof ( void * ) , 1 , f );

  return ( ret );
}

/****************************************************************************/

int List::Load ( FILE *f )
{
  int ret = TRUE;

/* Levanto las propiedades del objeto */
  fread ( this , sizeof ( List ) , 1 , f );

/* Alloco espacio para todas las propiedades */
  this -> elementos = ( void ** ) malloc ( this -> len * sizeof ( void * ) );

/* Levanto toda la lista de elementos */
  fread ( this -> elementos , this -> len * sizeof ( void * ) , 1 , f );

  return ( ret );
}

/****************************************************************************/
/****************************************************************************/
