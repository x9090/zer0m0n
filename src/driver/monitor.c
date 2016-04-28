#include "monitor.h"
#include "main.h"

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//      Initialize the linked lists
//  Parameters :
//      None
//  Return value :
//      None
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Init_LinkedLists(VOID)
{
	PPROCESS_ENTRY pInitHideEntry = NULL;
	PPROCESS_ENTRY pInitProcEntry = NULL;	
	pMonitoredProcessListHead = NULL;
	pHiddenProcessListHead = NULL;
	pHandleListHead = NULL;

	pInitHideEntry = AllocateProcessEntry(0);
	if(pInitHideEntry == NULL)
	{
		Dbg(__FUNCTION__ ":\tAllocation failed !\n");
		return STATUS_NO_MEMORY;
	}
	pInitProcEntry = AllocateProcessEntry(0);
	if(pInitProcEntry == NULL)
	{
		Dbg(__FUNCTION__ ":\tAllocation failed !\n");
		return STATUS_NO_MEMORY;
	}

	InitializeListHead(&pInitProcEntry->entry);            
	pMonitoredProcessListHead = &pInitProcEntry->entry;
	InitializeListHead(&pInitHideEntry->entry);            
	pHiddenProcessListHead = &pInitHideEntry->entry;

	return STATUS_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//      Allocate a new node for a process linked list 
//  Parameters :
//      __in ULONG new_pid : PID to add to the list
//  Return value :
//      PPROCESS_ENTRY : an allocated PROCESS_ENTRY or NULL if an error occured
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
PPROCESS_ENTRY AllocateProcessEntry(__in ULONG new_pid)
{
	PPROCESS_ENTRY pProcessEntry = NULL;

	pProcessEntry = PoolAlloc(sizeof(PROCESS_ENTRY));
	if(pProcessEntry == NULL)
	{
		Dbg(__FUNCTION__ ": failed !\n");
		return NULL;
	}

	pProcessEntry->pid = new_pid;

	return pProcessEntry;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//      Allocate a new node for a process linked list 
//  Parameters :
//      __in HANDLE new_handle : handle to add to the list
//  Return value :
//      PHANDLE_ENTRY : an allocated HANLE_ENTRY or NULL if an error occured 
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
PHANDLE_ENTRY AllocateHandleEntry(__in HANDLE new_handle)
{
	PHANDLE_ENTRY pHandleEntry = NULL;

	pHandleEntry = PoolAlloc(sizeof(HANDLE_ENTRY));
	if(pHandleEntry == NULL)
	{
		Dbg(__FUNCTION__ ": failed !\n"); 
		return NULL;
	}
	pHandleEntry->handle = new_handle;

	return pHandleEntry;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//      Add a new process to monitor in the list 
//  Parameters :
//      __in ULONG new_pid : pid to add to the list
//  Return value :
//      NTSTATUS : STATUS_SUCCESS if no error occured, otherwise returns the relevant NTSTATUS code
//  Process :
//      Add the pid in the list if he's not already inside.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS StartMonitoringProcess(__in ULONG new_pid)
{
	PPROCESS_ENTRY pNewEntry = NULL;

	if(new_pid == 0)
		return STATUS_INVALID_PARAMETER;

	if(IsProcessInList(new_pid, pMonitoredProcessListHead))
	{
		Dbg(__FUNCTION__ ":\t%d deja dans la liste : %d\n", new_pid);
		return STATUS_SUCCESS;
	}

	pNewEntry = AllocateProcessEntry(new_pid);
	if(pNewEntry == NULL)
	{
		Dbg(__FUNCTION__ ":\tAllocation failed !\n");
		return STATUS_NO_MEMORY;
	}	
	InsertHeadList(pMonitoredProcessListHead, &pNewEntry->entry);        
	return STATUS_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//      Add a new process to hide in the list 
//  Parameters :
//      __in ULONG new_pid : pid to add to the list
//  Return value :
//      NTSTATUS : STATUS_SUCCESS if no error occured, otherwise returns the relevant NTSTATUS code
//  Process :
//      Add the pid in the list if he's not already inside.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS AddProcessToHideToList(__in ULONG new_pid)
{
	PPROCESS_ENTRY pNewEntry = NULL;

	if(new_pid == 0)
		return STATUS_INVALID_PARAMETER;
	if(IsProcessInList(new_pid, pHiddenProcessListHead))
	{
		Dbg(__FUNCTION__ "\t: process to hide %d deja dans la liste : %d\n", new_pid);
		return STATUS_SUCCESS;
	}
	pNewEntry = AllocateProcessEntry(new_pid);
	if(pNewEntry == NULL)
	{
		Dbg(__FUNCTION__ "pNewEntry allocation failed !\n");
		return STATUS_NO_MEMORY;
	}

	InsertHeadList(pHiddenProcessListHead, &pNewEntry->entry);        
	return STATUS_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//      Add a new handle to monitor in the list 
//  Parameters :
//      __in ULONG new_handle : new_handle to add in the list
//  Return value :
//      NTSTATUS : STATUS_SUCCESS if no error occured, otherwise returns the relevant NTSTATUS code
//  Process :
//      Add the handle in the list if he's not already inside.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS AddHandleToList(__in HANDLE new_handle)
{    
	PHANDLE_ENTRY pNewEntry = NULL;

	if(new_handle == 0)
		return STATUS_INVALID_PARAMETER;
	if(IsHandleInList(new_handle))
	{
		Dbg(__FUNCTION__ "\t: handle %d deja dans la liste : %d\n", new_handle);
		return STATUS_SUCCESS;
	}	

	if(pHandleListHead == NULL)
	{
		pNewEntry = AllocateHandleEntry(0);
		if(pNewEntry == NULL)
		{
			Dbg(__FUNCTION__ ": failed !\n");
			return STATUS_NO_MEMORY;
		}
		InitializeListHead(&pNewEntry->entry);            
		pHandleListHead = &pNewEntry->entry;
	}

	pNewEntry = AllocateHandleEntry(new_handle);
	if(pNewEntry == NULL)
	{
		Dbg(__FUNCTION__ ": failed !\n");
		return STATUS_NO_MEMORY;
	}    
	InsertHeadList(pHandleListHead, &pNewEntry->entry);        
	return STATUS_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//      Removes handle from the list (stop monitoring this handle) 
//  Parameters :
//      __in ULONG handle : handle to remove from the monitored handle list 
//  Return value :
//      NTSTATUS : STATUS_SUCCESS if no error occured, otherwise, relevant NTSTATUS code
//  Process :
//      Remove handle from the list if he's inside.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS RemoveHandleFromList(__in HANDLE handle)
{
	PLIST_ENTRY pListEntry = NULL;
	PHANDLE_ENTRY pCurEntry = NULL;

	if(handle == 0)
		return STATUS_INVALID_PARAMETER;

	if(!IsHandleInList(handle))
		return STATUS_SUCCESS;

	pListEntry = pHandleListHead->Flink;
	do
	{
		pCurEntry = (PHANDLE_ENTRY) CONTAINING_RECORD(pListEntry, HANDLE_ENTRY, entry);
		if(pCurEntry->handle == handle)
		{
			RemoveEntryList(&pCurEntry->entry);
			return STATUS_SUCCESS; 
		}

		pListEntry = pListEntry->Flink;
	}
	while(pListEntry != pHandleListHead);

	return STATUS_SUCCESS;

}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//      Checks if a process is in a linked list 
//  Parameters :
//      __in ULONG pid : process identifier to check for
//      __in PLIST_ENTRY pListHead : linked list to check in
//  Return value :
//      BOOLEAN : TRUE if found, FALSE if not 
//  Process :
//      Walks through the linked list, returns TRUE if the process is found 
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
BOOLEAN IsProcessInList(__in ULONG pid, 
		__in PLIST_ENTRY pListHead)
{

	PLIST_ENTRY pListEntry = NULL;
	PPROCESS_ENTRY pCurEntry = NULL;

	if(pListHead == NULL)
		return FALSE;

	if(IsListEmpty(pListHead))
		return FALSE;

	pListEntry = pListHead->Flink;
	do
	{
		pCurEntry = CONTAINING_RECORD(pListEntry, PROCESS_ENTRY, entry);
		if(pCurEntry->pid == pid)
			return TRUE;

		pListEntry = pListEntry->Flink;   
	} 
	while(pListEntry != pListHead);

	return FALSE;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//      Checks if a handle is in a linked list 
//  Parameters :
//      __in HANDLE handle : handle to check for
//      __in PLIST_ENTRY pListHead : linked list to check in
//  Return value :
//      BOOLEAN : TRUE if found, FALSE if not 
//  Process :
//      Walks through the linked list, returns TRUE if the handle is found 
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
BOOLEAN IsHandleInList(__in HANDLE handle)
{
	PLIST_ENTRY pListEntry = NULL;
	PHANDLE_ENTRY pCurEntry = NULL;

	if(pHandleListHead == NULL)
		return FALSE;

	if(IsListEmpty(pHandleListHead))
		return FALSE;

	pListEntry = pHandleListHead->Flink;

	do
	{
		pCurEntry = (PHANDLE_ENTRY)CONTAINING_RECORD(pListEntry, HANDLE_ENTRY, entry);
		if(pCurEntry->handle == handle)
			return TRUE;

		pListEntry = pListEntry->Flink;   
	}
	while(pListEntry != pHandleListHead);

	return FALSE;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//      Remove the entries from every linked list 
//  Parameters :
//      None
//  Return value :
//      None
//  Process :
//      Walks through the linked lists and removes each entries.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID FreeList(VOID)
{
	PLIST_ENTRY pListEntry = NULL; 
	PLIST_ENTRY pNextEntry = NULL;
	PPROCESS_ENTRY pCurProcEntry = NULL;
	PHANDLE_ENTRY pCurHandleEntry = NULL;

	if(pMonitoredProcessListHead != NULL)
	{
		if(!IsListEmpty(pMonitoredProcessListHead))
		{
			pListEntry = pMonitoredProcessListHead->Flink;
			do
			{
				pCurProcEntry = (PPROCESS_ENTRY)CONTAINING_RECORD(pListEntry, PROCESS_ENTRY, entry);
				pNextEntry = pListEntry->Flink;
				ExFreePool(pCurProcEntry);
				pListEntry = pNextEntry;
			}
			while(pListEntry != pMonitoredProcessListHead);
			pMonitoredProcessListHead = NULL;
		}
	}

	if(pHiddenProcessListHead != NULL)
	{
		if(!IsListEmpty(pHiddenProcessListHead))
		{
			pListEntry = pHiddenProcessListHead->Flink;
			do
			{
				pCurProcEntry = (PPROCESS_ENTRY)CONTAINING_RECORD(pListEntry, PROCESS_ENTRY, entry);
				pNextEntry = pListEntry->Flink;
				ExFreePool(pCurProcEntry);
				pListEntry = pNextEntry;
			}
			while(pListEntry != pHiddenProcessListHead);
			pHiddenProcessListHead = NULL;
		}
	}

	if(pHandleListHead != NULL)
	{
		if(!IsListEmpty(pHandleListHead))
		{
			pListEntry = pHandleListHead->Flink;
			do
			{
				pCurProcEntry = (PPROCESS_ENTRY)CONTAINING_RECORD(pListEntry, HANDLE_ENTRY, entry);
				pNextEntry = pListEntry->Flink;
				ExFreePool(pCurProcEntry);
				pListEntry = pNextEntry;
			}
			while(pListEntry != pHandleListHead);
			pHandleListHead = NULL;
		}

	}
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//      Displays each entries from the linked listed 
//  Parameters :
//      None
//  Return value :
//      None
//  Process :
//      Walks through the linked lists and display each entries (only use for debug purposes).
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID Dbg_WalkList(VOID)
{
	PLIST_ENTRY pListEntry = NULL;
	PPROCESS_ENTRY pCurProcEntry = NULL;
	PHANDLE_ENTRY pCurHandleEntry = NULL;
	ULONG i = 1;

	if(pMonitoredProcessListHead != NULL)
	{
		Dbg("pMonitoredProcessListHead n'est pas null\n");
		if(IsListEmpty(pMonitoredProcessListHead))
		{
			Dbg("The monitored process list is empty\n");
		}
		else
		{
			pListEntry = pMonitoredProcessListHead->Flink;
			Dbg("\nWalk through the monitored process list\n");
			do
			{
				pCurProcEntry = (PPROCESS_ENTRY)CONTAINING_RECORD(pListEntry, PROCESS_ENTRY, entry);
				Dbg("\tENTRY %d => pid : %d\n", i, pCurProcEntry->pid);
				pListEntry = pListEntry->Flink;   
				i++;
			}
			while(pListEntry != pMonitoredProcessListHead);
		}
	}

	if(pHiddenProcessListHead != NULL)
	{
		if(IsListEmpty(pHiddenProcessListHead))
		{
			Dbg("The hidden process list is empty\n");
		}
		else
		{
			pListEntry = pHiddenProcessListHead->Flink;
			Dbg("Walk through the hidden process list\n");
			do
			{
				pCurProcEntry = (PPROCESS_ENTRY)CONTAINING_RECORD(pListEntry, PROCESS_ENTRY, entry);
				Dbg("\tENTRY %d => pid : %d\n", i, pCurProcEntry->pid);
				pListEntry = pListEntry->Flink;   
				i++;
			}
			while(pListEntry != pHiddenProcessListHead);
		}
	}

	if(pHandleListHead != NULL)
	{
		if(IsListEmpty(pHandleListHead))
		{
			Dbg("The handle list is empty\n");
		}
		else
		{		
			pListEntry = pHandleListHead->Flink;
			Dbg("Walk through the handle list\n");
			do
			{
				pCurHandleEntry = (PHANDLE_ENTRY)CONTAINING_RECORD(pListEntry, HANDLE_ENTRY, entry);
				Dbg("\tENTRY %d => handle : %d\n", i, pCurHandleEntry->handle);
				pListEntry = pListEntry->Flink;   
				i++;
			}
			while(pListEntry != pHandleListHead);
		}
	}
}
