import { Admin, Resource } from "react-admin";
import { authProvider } from "./authProvider";
import { dataProvider } from "./dataProvider";
import { UserList, UserEdit, UserCreate } from "./users";
import { ContainerEdit, ContainerList } from "./containers";

export default function App() {
  return (
    <Admin
      title="IAM Console"
      authProvider={authProvider}
      dataProvider={dataProvider}
    >
      <Resource
        name="user"
        list={UserList}
        edit={UserEdit}
        create={UserCreate}
      />
      <Resource
        name="server/prx/lxc/list/all"
        list={ContainerList}
        edit={ContainerEdit}
      />
      {/* Add more resources here */}
    </Admin>
  );
}
