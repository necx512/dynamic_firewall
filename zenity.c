#include<stdlib.h>  
#include<gtk/gtk.h>  
  
void ma_function(int argc, char *argv[])
{
	GtkWidget *mafenetre;  
	gtk_init(&argc,&argv);  
	mafenetre=gtk_window_new(GTK_WINDOW_TOPLEVEL); 
	GtkWidget *maboitededialog = gtk_message_dialog_new(GTK_WINDOW(mafenetre), GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_QUESTION, GTK_BUTTONS_YES_NO, "Voulez-vous reelement quitter?");  
	switch(gtk_dialog_run(GTK_DIALOG(maboitededialog)))  
	{  
		case GTK_RESPONSE_YES://GTK_RESPONSE_YES valeur de retour du bouton YES  
	                printf("YES\n");
	        	break;  
	        case GTK_RESPONSE_NO://GTK_RESPONSE_NO valeur de retour du bouton NO  
	              gtk_widget_destroy(maboitededialog);  
	              printf("NO\n");
	              break;  
	}
}	
int main(int argc, char *argv[])  
{
       for(int i=0;i<10;++i)
       {
	       printf("%d\n",i);
	       pid_t child = fork();
	       if(child == 0){
			ma_function(argc, argv);
			exit(0);
	       }
	       else{
		       sleep(10);
	       }
	}	       
}  
