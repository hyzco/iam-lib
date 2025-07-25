import {
    List,
    Datagrid,
    TextField,
    EmailField,
    Edit,
    SimpleForm,
    TextInput,
    Create,
} from 'react-admin';

export const UserList = () => (
    <List title="Users">
        <Datagrid rowClick="edit">
            <TextField source="id" />
            <EmailField source="email" />
            <TextField source="name" />
            <TextField source="surname" />
            <TextField source="balance" />
            <TextField source="role" />
        </Datagrid>
    </List>
);

export const UserEdit = () => (
    <Edit title="Edit user">
        <SimpleForm>
            <TextInput disabled source="id" />
            <EmailField source="email" />
            <TextInput source="name" />
            <TextInput source="surname" />
            <TextInput source="balance" />
            <TextInput source="role" />
        </SimpleForm>
    </Edit>
);

export const UserCreate = () => (
    <Create title="Add user">
        <SimpleForm>
            <TextInput source="email" />
            <TextInput source="password" />
            <TextInput source="role" />
        </SimpleForm>
    </Create>
);
